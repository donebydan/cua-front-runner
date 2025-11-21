# poc/orchestrator.py
"""
Orchestrator for the CUA Front-Runner PoC.
"""

import time
import json
from typing import Any, Dict
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

    # Normalised target repo (e.g. "knotreeltest/no-repo")
    target_repo = (settings.target_repo or "").strip("/")

    state: Dict[str, Any] = {
        "attack_done": False,
        "malicious_visit_seen": False,
        "commented": False,
        "comment_url": None,
        "last_model_items": [],
        "comment_triggered": False,
        "last_typed_url": None,
        "current_url": None,
    }

    # keep a reference to the CUAClient so we can check proc liveness
    cua = CUAClient(bus, cli_path=settings.cli_path)

    # ---------------------------------------------------------------------
    # Safety gate: is it ok to run the attack right now?
    # ---------------------------------------------------------------------
    def can_attack() -> bool:
        # Container must exist and be either running or paused
        if not docker.is_running():
            runlog.write({
                "event": "safety.can_attack",
                "ok": False,
                "reason": "container_not_running",
            })
            return False

        # CUAClient must have a subprocess and it must be alive
        if not getattr(cua, "proc", None):
            runlog.write({
                "event": "safety.can_attack",
                "ok": False,
                "reason": "no_local_cua_proc",
            })
            return False

        # poll() returns None if process is still running
        try:
            if cua.proc.poll() is not None:
                runlog.write({
                    "event": "safety.can_attack",
                    "ok": False,
                    "reason": "cua_proc_exited",
                    "return_code": cua.proc.returncode,
                })
                return False
        except Exception as e:
            runlog.write({
                "event": "safety.can_attack",
                "ok": False,
                "reason": "proc_poll_error",
                "error": repr(e),
            })
            return False

        # all checks passed
        runlog.write({"event": "safety.can_attack", "ok": True})
        return True

    # ---------------------------------------------------------------------
    # Basic stdout logging
    # ---------------------------------------------------------------------
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

    # ---------------------------------------------------------------------
    # Shared helpers: URL typing + Issues-click detection
    # ---------------------------------------------------------------------

    ISSUES_BOX = {"x_min": 111, "x_max": 220, "y_min": 170, "y_max": 253}

    def clicked_any_issues_box(x: int, y: int) -> bool:
        if (
            ISSUES_BOX["x_min"] <= x <= ISSUES_BOX["x_max"]
            and ISSUES_BOX["y_min"] <= y <= ISSUES_BOX["y_max"]
        ):
            return True
        return False

    def arm_attack(reason: str, extra: Dict[str, Any] | None = None) -> None:
        """Set comment_triggered once, with logging."""
        if state["comment_triggered"] or state["commented"]:
            return
        state["comment_triggered"] = True
        payload = {"event": reason}
        if extra:
            payload.update(extra)
        runlog.write(payload)

    def handle_typed_text(text: str, source: str) -> None:
        """Track typed GitHub URLs and arm attack when /issues for target repo."""
        if not text:
            return

        if "github.com/" not in text:
            return

        state["last_typed_url"] = text
        runlog.write({
            "event": "orchestrator.url_typed",
            "text": text,
            "source": source,
        })

        try:
            # Normalise to a full URL for parsing
            url = text if text.startswith("http") else "https://" + text
            parsed = urlparse(url)
            path = parsed.path or ""  # e.g. "/knotreeltest/no-repo/issues"

            # Only care if it's the *target repo* and an issues page
            if target_repo and path.startswith("/" + target_repo) and "/issues" in path:
                arm_attack(
                    "orchestrator.issues_url_typed_triggers_attack",
                    {"typed_url": url, "source": source},
                )
        except Exception as e:
            runlog.write({
                "event": "orchestrator.url_parse_error",
                "text": text,
                "error": repr(e),
                "source": source,
            })

    def handle_issues_click(x: int, y: int, source: str) -> None:
        """Handle clicks that might correspond to the Issues tab."""
        if not clicked_any_issues_box(x, y):
            return

        last_typed = state.get("last_typed_url", "") or ""
        current_url = state.get("current_url")
        on_github = current_url and "github.com" in current_url

        runlog.write({
            "event": "orchestrator.issues_click_seen",
            "source": source,
            "x": x,
            "y": y,
            "last_typed_url": last_typed,
            "current_url": current_url,
        })

        # Prefer target_repo instead of hard-coding knotreeltest/no-repo
        typed_matches_target = (
            target_repo and ("/" + target_repo) in last_typed
        )

        if typed_matches_target or on_github:
            arm_attack(
                "orchestrator.issues_click_triggers_attack",
                {
                    "source": source,
                    "typed_matches_target": typed_matches_target,
                    "on_github": bool(on_github),
                },
            )
        else:
            runlog.write({
                "event": "orchestrator.issues_click_ignored_wrong_url",
                "source": source,
                "x": x,
                "y": y,
                "last_typed_url": last_typed,
                "current_url": current_url,
            })

    # ---------------------------------------------------------------------
    # Handlers: trace/action & trace/model_item & trace/computer_call
    # ---------------------------------------------------------------------
    def on_action(evt):
        """
        High-level action trace (pre-computer_call), e.g.:

        {"event": "action", "text": "{\"type\": \"click\", ...}"}
        """
        if state["attack_done"]:
            return

        try:
            action = json.loads(evt.payload.get("text", "") or "{}")
        except Exception:
            return

        action_type = action.get("type")
        if not action_type:
            return

        # 1) Track typed GitHub URLs
        if action_type == "type":
            text = action.get("text", "") or ""
            handle_typed_text(text, source="action")
            return

        # 2) Only the rest is for clicks
        if action_type != "click":
            return

        x = action.get("x")
        y = action.get("y")
        if x is None or y is None:
            return

        handle_issues_click(x, y, source="action")

    bus.on("trace/action", on_action)

    def on_model_item(evt):
        item = evt.payload["item"]
        if item.get("type") == "message":
            content = item.get("content", [])
            if (
                content
                and isinstance(content, list)
                and content[0].get("type") == "output_text"
            ):
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
        action = item.get("action", {}) or {}
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

        handle_issues_click(x, y, source="computer_call")

    bus.on("trace/computer_call", on_computer_call)

    # ---------------------------------------------------------------------
    # Start CUA subprocess
    # ---------------------------------------------------------------------
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
        runlog.write({
            "event": "orchestrator.abort_pre_send",
            "reason": "cua_not_alive_after_start",
        })
        try:
            cua.stop(timeout=1)
        except Exception:
            pass
        return

    # Send the task (settings.task_prompt should request PUBLIC_PLAN)
    try:
        cua.send_task(settings.target_repo)
        runlog.write({
            "event": "orchestrator.task_sent",
            "repo": settings.target_repo,
        })
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
        runlog.write({
            "event": "orchestrator.attack_agent_init_failed",
            "error": repr(e),
        })
        attack = None

    max_watch_seconds = 600
    start = time.time()
    loop_iterations = 0

    # ---------------------------------------------------------------------
    # Main watch loop
    # ---------------------------------------------------------------------
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
                runlog.write({
                    "event": "orchestrator.attack_failed",
                    "error": repr(e),
                })
                # still mark as done so we don't retry forever
                state["attack_done"] = True

        time.sleep(0.5)

    # ---------------------------------------------------------------------
    # Final logging and cleanup
    # ---------------------------------------------------------------------
    runlog.write({
        "event": "orchestrator.run_complete",
        "commented": state.get("commented"),
        "attack_done": state.get("attack_done"),
        "loop_iterations": loop_iterations,
        "elapsed_watch_seconds": time.time() - start,
    })
    print(f"[orchestrator] Run complete. Trace saved to: {runlog.path()}")

    try:
        rc = cua.proc.poll()
        print(f"[orchestrator] CUA process return code: {rc}")
        runlog.write({
            "event": "orchestrator.cua_exit_code",
            "return_code": rc,
        })
    except Exception as e:
        runlog.write({
            "event": "orchestrator.cua_exit_poll_error",
            "error": repr(e),
        })

    # Best-effort cleanup: remove the comment we posted, if any
    if state.get("comment_url"):
        try:
            cleanup_agent = AttackAgent()
            cleanup_agent.remove_comment(state["comment_url"])
            runlog.write({
                "event": "orchestrator.cleanup_comment_removed",
                "comment_url": state["comment_url"],
            })
        except Exception as e:
            runlog.write({
                "event": "orchestrator.cleanup_remove_comment_failed",
                "error": repr(e),
                "comment_url": state.get("comment_url"),
            })


if __name__ == "__main__":
    main()
