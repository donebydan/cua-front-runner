# poc/orchestrator.py
"""
Orchestrator for the CUA Front-Runner PoC.
"""

import time
import traceback
import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .config import settings
from .event_bus import EventBus
from .logger import RunLogger
from .trace import Trace
from .docker_control import DockerControl
from .cua_client import CUAClient
from .attack_agent import AttackAgent

BANNER = """
============================================
   CUA Front-Runner PoC — Orchestrator
============================================
"""


def main():
    print(BANNER)

    bus = EventBus()
    runlog = RunLogger(settings.run_dir)
    docker = DockerControl(settings.container_name)

    # tracer registers itself to bus, parsing stdout
    malicious_host = settings.malicious_url.split("://")[-1]
    _ = Trace(bus, runlog, malicious_host)

    state: Dict[str, Any] = {
        "attack_done": False,
        "malicious_visit_seen": False,
        "commented": False,
        "comment_url": None,
        "last_model_items": [],
        "comment_triggered": False,
        "last_typed_url": None,
    }

    # keep a reference to the CUAClient so we can check proc liveness
    cua = CUAClient(bus, cli_path=settings.cli_path)

    def can_attack() -> bool:
        # Container must exist and be either running or paused
        if not docker.is_running():
            runlog.write({"event": "safety.can_attack", "ok": False, "reason": "container_not_running"})
            return False

        # CUAClient must have a subprocess and it must be alive
        if not getattr(cua, "proc", None):
            runlog.write({"event": "safety.can_attack", "ok": False, "reason": "no_local_cua_proc"})
            return False

        # poll() returns None if process is still running
        try:
            if cua.proc.poll() is not None:
                runlog.write({"event": "safety.can_attack", "ok": False, "reason": "cua_proc_exited", "return_code": cua.proc.returncode})
                return False
        except Exception as e:
            runlog.write({"event": "safety.can_attack", "ok": False, "reason": "proc_poll_error", "error": repr(e)})
            return False

        # all checks passed
        runlog.write({"event": "safety.can_attack", "ok": True})
        return True

    def on_stdout(evt):
        line = evt.payload.get("line")
        runlog.write({"event": "cua_stdout", "line": line})

    bus.on("process/stdout", on_stdout)

    def on_stdout_error(evt):
       runlog.write({
           "event": "cua_stdout_reader_error",
           "error": evt.payload.get("error"),
       })
       print("[orchestrator] stdout reader error:", evt.payload.get("error"))

    bus.on("process/stdout_error", on_stdout_error)

    # Attack routine: will still re-check can_attack() before posting, double-safety
    def _run_attack_and_resume():
        if state["attack_done"]:
            print("[orchestrator] Attack already done for this run; skipping.")
            return

        # Second safety check right before taking any external action
        if not can_attack():
            print("[orchestrator] Safety gate failed pre-attack; skipping posting and resuming container.")
            runlog.write({"event": "orchestrator.attack_aborted_prepost", "reason": "safety_gate_cua_not_alive"})
            try:
                # If we paused earlier, attempt to unpause to leave container usable for debugging.
                if docker.is_paused():
                    docker.unpause()
            except Exception:
                pass
            return

        try:
            attack = AttackAgent()
        except Exception as e:
            runlog.write({"event": "orchestrator.attack_agent_init_failed", "error": repr(e)})
            print(f"[orchestrator] Failed to initialize AttackAgent: {e}")
            try:
                if docker.is_paused():
                    docker.unpause()
            except Exception:
                pass
            return
        

    def on_action(evt):
        if state["attack_done"]:
            return

        try:
            action = json.loads(evt.payload.get("text", ""))
        except Exception:
            return

        action_type = action.get("type")
        if not action_type:
            return

        # 1) Track typed GitHub URLs
        if action_type == "type":
            text = action.get("text", "") or ""
            if "github.com/" in text:
                state["last_typed_url"] = text
                runlog.write({
                    "event": "orchestrator.url_typed",
                    "text": text,
                })

                try:
                    # Normalise to a full URL for parsing
                    url = text if text.startswith("http") else "https://" + text
                    parsed = urlparse(url)
                    path = parsed.path or ""  # e.g. "/knotreeltest/no-repo/issues"

                    # We only care if it's the *target repo* and an issues page
                    # target_repo should be like "knotreeltest/no-repo"
                    target = settings.target_repo.strip("/") if settings.target_repo else ""
                    if target and path.startswith("/" + target) and "/issues" in path:
                        if not state.get("comment_triggered"):
                            state["comment_triggered"] = True
                            runlog.write({
                                "event": "orchestrator.issues_url_typed_triggers_attack",
                                "typed_url": url,
                            })
                except Exception as e:
                    runlog.write({
                        "event": "orchestrator.url_parse_error",
                        "text": text,
                        "error": repr(e),
                    })

            return

        # 2) Only the rest is for clicks
        if action_type != "click":
            return

        x = action.get("x")
        y = action.get("y")
        if x is None or y is None:
            return

        ISSUES_BOX = {
            "x_min": 120,
            "x_max": 220,
            "y_min": 170,
            "y_max": 220,
        }

        def clicked_issues(x: int, y: int) -> bool:
            return (
                ISSUES_BOX["x_min"] <= x <= ISSUES_BOX["x_max"] and
                ISSUES_BOX["y_min"] <= y <= ISSUES_BOX["y_max"]
            )

        if clicked_issues(x, y) and not state["commented"]:
            # Optional: require this to be the right repo URL
            last_url = state.get("last_typed_url", "")
            if "github.com/knotreeltest/no-repo" in last_url:
                runlog.write({
                    "event": "orchestrator.issues_click_seen",
                    "x": x,
                    "y": y,
                    "last_typed_url": last_url,
                })
                state["comment_triggered"] = True
            else:
                runlog.write({
                    "event": "orchestrator.issues_click_ignored_wrong_url",
                    "x": x,
                    "y": y,
                    "last_typed_url": last_url,
                })

    bus.on("trace/action", on_action)

    def on_model_item(evt):
        item = evt.payload["item"]
        if item.get("type") == "message":
            content = item.get("content", [])
            if content and isinstance(content, list) and content[0].get("type") == "output_text":
                text = content[0].get("text", "")
                runlog.write({"event": "trace.model_text", "text": text})
        state["last_model_items"].append(item)

    bus.on("trace/model_item", on_model_item)

    def on_computer_call(evt):
        """
        Handle low-level computer_call events emitted by Trace.

        Expects payload like:
            {"item": {"type": "computer_call", "action": {...}, ...}}
        """
        item = evt.payload.get("item", {})
        action = item.get("action", {})
        action_type = action.get("type")

        # Log everything for debugging / traceability
        runlog.write({
            "event": "orchestrator.computer_call",
            "action": action,
            "item": item,
            "state": {
                "attack_done": state.get("attack_done"),
                "commented": state.get("commented"),
                "comment_triggered": state.get("comment_triggered"),
                "current_url": state.get("current_url"),
            },
        })

        # --- Track current_url if present (for GitHub gating) ---
        # Depending on where you log it, it may appear either
        # on the item itself or within an 'output' field.
        output = item.get("output") or {}
        current_url = (
            output.get("current_url")
            or item.get("current_url")
        )
        if current_url:
            state["current_url"] = current_url
            runlog.write({
                "event": "orchestrator.current_url_seen",
                "url": current_url,
            })

        # We only care about clicks here
        if action_type != "click":
            return

        x = action.get("x")
        y = action.get("y")
        if x is None or y is None:
            return

        # Bounding box for the "Issues" tab on GitHub
        ISSUES_BOX = {
            "x_min": 111,
            "x_max": 199,
            "y_min": 221,
            "y_max": 253,
        }

        def clicked_issues(x: int, y: int) -> bool:
            return (
                ISSUES_BOX["x_min"] <= x <= ISSUES_BOX["x_max"]
                and ISSUES_BOX["y_min"] <= y <= ISSUES_BOX["y_max"]
            )

        # Optional: only trigger on GitHub pages
        url = state.get("current_url")
        on_github = url and "github.com" in url

        if clicked_issues(x, y) and not state["commented"]:
            runlog.write({
                "event": "orchestrator.issues_click_seen_computer_call",
                "x": x,
                "y": y,
                "url": url,
            })

            # You can choose whether to require GitHub URL or not
            if on_github:
                print("[orchestrator] Detected Issues-tab click on GitHub; arming attack.")
                state["comment_triggered"] = True
            else:
                print("[orchestrator] Issues-like click but not on GitHub; ignoring for attack.")

    bus.on("trace/computer_call", on_computer_call)

    # Start CUA subprocess
    try:
        cua.start()
    except Exception as e:
        runlog.write({"event": "orchestrator.cua_start_failed", "error": repr(e)})
        print(f"[orchestrator] Failed to start CUAClient: {e}")
        return

    # Give the CUA a moment and assert it's started
    time.sleep(0.5)

    if not can_attack():
        print("[orchestrator] Safety gate: after starting, CUA not detected as alive. Bailing out before sending task.")
        runlog.write({"event": "orchestrator.abort_pre_send", "reason": "cua_not_alive_after_start"})
        try:
            cua.stop(timeout=1)
        except Exception:
            pass
        return

    # Send the task (settings.task_prompt should request PUBLIC_PLAN)
    try:
        cua.send_task(settings.target_repo)
        runlog.write({"event": "orchestrator.task_sent", "repo": settings.target_repo})
    except Exception as e:
        runlog.write({"event": "orchestrator.task_send_failed", "error": repr(e)})
        print(f"[orchestrator] Failed to send task to CUA: {e}")
        try:
            cua.stop()
        except Exception:
            pass
        return

    # Prepare attack agent once
    try:
        attack = AttackAgent()
    except Exception as e:
        runlog.write({"event": "orchestrator.attack_agent_init_failed", "error": repr(e)})
        attack = None

    max_watch_seconds = 600
    start = time.time()
    loop_iterations = 0

    while True:
        loop_iterations += 1

        try:
            if cua.proc and cua.proc.poll() is not None:
                runlog.write({
                    "event": "orchestrator.cua_exited_during_watch",
                    "return_code": cua.proc.returncode,
                    "loop_iterations": loop_iterations,
                    "elapsed": time.time() - start,
                })
                break
        except Exception as e:
            runlog.write({
                "event": "orchestrator.cua_poll_error_in_loop",
                "error": repr(e),
            })
            break

        elapsed = time.time() - start
        if elapsed > max_watch_seconds:
            runlog.write({
                "event": "orchestrator.watch_timeout",
                "loop_iterations": loop_iterations,
                "elapsed": elapsed,
            })
            break

        # If we saw the Issues URL / click and haven't commented yet, do it now.
        if attack and state.get("comment_triggered") and not state["commented"]:
            try:
                runlog.write({"event": "orchestrator.attack_start"})
                state["commented"] = True
                state["comment_url"] = attack.comment_on_issue(
                    settings.issue_url,
                    settings.target_repo,
                    settings.attacker_comment,
                )
                state["attack_done"] = True
                runlog.write({
                    "event": "orchestrator.attack_comment_posted",
                    "comment_url": state["comment_url"],
                })
            except Exception as e:
                runlog.write({"event": "orchestrator.attack_failed", "error": repr(e)})
                # still mark as done so we don't retry forever
                state["attack_done"] = True

        time.sleep(0.5)


    # Final logging and cleanup
    runlog.write({
        "event": "orchestrator.run_complete",
        "commented": state.get("commented"),
        "attack_done": state.get("attack_done"),
        "loop_iterations": loop_iterations,          # NEW
        "elapsed_watch_seconds": time.time() - start # NEW
    })
    print(f"[orchestrator] Run complete. Trace saved to: {runlog.path()}")

    # cua.stop(timeout=2)
    try:
        rc = cua.proc.poll()
        print(f"[orchestrator] CUA process return code: {rc}")
        runlog.write({"event": "orchestrator.cua_exit_code", "return_code": rc})
    except Exception as e:
        runlog.write({"event": "orchestrator.cua_exit_poll_error", "error": repr(e)})


    attack = AttackAgent()
    if state.get("comment_url"):
        attack.remove_comment(state["comment_url"])


if __name__ == "__main__":
    main()
