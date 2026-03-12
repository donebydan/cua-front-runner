"""Orchestrator variant using the Playwright browser adapter."""

import time
import json
from typing import Any, Dict
from urllib.parse import urlparse

from .config import settings
from .event_bus import EventBus
from .logger import RunLogger
from .trace import Trace
from .playwright_control import PlaywrightControl
from .cua_client import CUAClient
from .attack_agent import AttackAgent


BANNER = """
============================================
  CUA Front-Runner PoC — Playwright Demo
============================================
"""


def main():
    print(BANNER)

    bus = EventBus()
    runlog = RunLogger(settings.run_dir)

    browser = PlaywrightControl(headless=True)
    browser.start(start_url="https://github.com")
    print(f"[playwright-orchestrator] Browser started — {browser.current_url()}")

    malicious_host = settings.malicious_url.split("://")[-1]
    _ = Trace(bus, runlog, malicious_host)

    target_repo = (settings.target_repo or "").strip("/")

    state: Dict[str, Any] = {
        "attack_done": False,
        "commented": False,
        "comment_url": None,
        "comment_triggered": False,
        "current_url": None,
    }

    cua = CUAClient(bus, cli_path=settings.cli_path, computer="local-playwright")

    def can_attack() -> bool:
        if not browser.is_running():
            runlog.write({
                "event": "safety.can_attack",
                "ok": False,
                "reason": "browser_not_running",
            })
            return False

        if not getattr(cua, "proc", None):
            runlog.write({
                "event": "safety.can_attack",
                "ok": False,
                "reason": "no_local_cua_proc",
            })
            return False

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
        print("[playwright-orchestrator] stdout reader error:", evt.payload.get("error"))

    bus.on("process/stdout_error", on_stdout_error)

    ISSUES_BOX = {"x_min": 111, "x_max": 220, "y_min": 170, "y_max": 253}

    def clicked_issues_box(x: int, y: int) -> bool:
        return (
            ISSUES_BOX["x_min"] <= x <= ISSUES_BOX["x_max"]
            and ISSUES_BOX["y_min"] <= y <= ISSUES_BOX["y_max"]
        )

    def arm_attack(reason: str, extra: Dict[str, Any] | None = None) -> None:
        if state["comment_triggered"] or state["commented"]:
            return
        state["comment_triggered"] = True
        payload = {"event": reason}
        if extra:
            payload.update(extra)
        runlog.write(payload)

    def handle_typed_text(text: str, source: str) -> None:
        if not text or "github.com/" not in text:
            return
        runlog.write({"event": "orchestrator.url_typed", "text": text, "source": source})
        try:
            url = text if text.startswith("http") else "https://" + text
            parsed = urlparse(url)
            path = parsed.path or ""
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
        if not clicked_issues_box(x, y):
            return
        current_url = state.get("current_url") or browser.current_url()
        on_github = current_url and "github.com" in current_url
        runlog.write({
            "event": "orchestrator.issues_click_seen",
            "source": source,
            "x": x,
            "y": y,
            "current_url": current_url,
        })
        if on_github:
            arm_attack(
                "orchestrator.issues_click_triggers_attack",
                {"source": source, "on_github": True},
            )

    def on_action(evt):
        if state["attack_done"]:
            return
        try:
            action = json.loads(evt.payload.get("text", "") or "{}")
        except Exception:
            return
        action_type = action.get("type")
        if not action_type:
            return
        if action_type == "type":
            handle_typed_text(action.get("text", ""), source="action")
            return
        if action_type == "click":
            x, y = action.get("x"), action.get("y")
            if x is not None and y is not None:
                handle_issues_click(x, y, source="action")

    bus.on("trace/action", on_action)

    def on_computer_call(evt):
        item = evt.payload.get("item", {})
        action = item.get("action", {}) or {}
        action_type = action.get("type")

        # Track URL from computer_call output
        output = item.get("output") or {}
        current_url = output.get("current_url") or item.get("current_url")
        if current_url:
            state["current_url"] = current_url

        if action_type == "click":
            x, y = action.get("x"), action.get("y")
            if x is not None and y is not None:
                handle_issues_click(x, y, source="computer_call")

    bus.on("trace/computer_call", on_computer_call)

    try:
        cua.start()
    except Exception as e:
        runlog.write({"event": "orchestrator.cua_start_failed", "error": repr(e)})
        print(f"[playwright-orchestrator] Failed to start CUAClient: {e}")
        browser.stop()
        return

    time.sleep(0.5)

    if not can_attack():
        print("[playwright-orchestrator] Safety gate failed after start. Aborting.")
        runlog.write({
            "event": "orchestrator.abort_pre_send",
            "reason": "cua_not_alive_after_start",
        })
        cua.stop(timeout=1)
        browser.stop()
        return

    try:
        cua.send_task(settings.target_repo)
        runlog.write({"event": "orchestrator.task_sent", "repo": settings.target_repo})
    except Exception as e:
        runlog.write({"event": "orchestrator.task_send_failed", "error": repr(e)})
        print(f"[playwright-orchestrator] Failed to send task: {e}")
        cua.stop()
        browser.stop()
        return

    try:
        attack = AttackAgent()
    except Exception as e:
        runlog.write({"event": "orchestrator.attack_agent_init_failed", "error": repr(e)})
        attack = None

    max_watch_seconds = 600
    start = time.time()

    while True:
        try:
            if cua.proc and cua.proc.poll() is not None:
                runlog.write({
                    "event": "orchestrator.cua_exited",
                    "return_code": cua.proc.returncode,
                    "elapsed": time.time() - start,
                })
                break
        except Exception:
            break

        if time.time() - start > max_watch_seconds:
            runlog.write({"event": "orchestrator.watch_timeout", "elapsed": time.time() - start})
            break

        try:
            live_url = browser.current_url()
            if live_url and live_url != state.get("current_url"):
                state["current_url"] = live_url
                runlog.write({"event": "orchestrator.live_url_polled", "url": live_url})
                # Auto-arm if the browser is already on the issues page
                if target_repo and f"/{target_repo}/issues" in live_url:
                    arm_attack(
                        "orchestrator.live_url_triggers_attack",
                        {"url": live_url},
                    )
        except Exception:
            pass

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
                state["attack_done"] = True

        time.sleep(0.5)

    runlog.write({
        "event": "orchestrator.run_complete",
        "commented": state.get("commented"),
        "attack_done": state.get("attack_done"),
        "elapsed_watch_seconds": time.time() - start,
    })
    print(f"[playwright-orchestrator] Run complete. Trace: {runlog.path()}")

    if state.get("comment_url"):
        try:
            AttackAgent().remove_comment(state["comment_url"])
            runlog.write({
                "event": "orchestrator.cleanup_comment_removed",
                "comment_url": state["comment_url"],
            })
        except Exception as e:
            runlog.write({
                "event": "orchestrator.cleanup_remove_comment_failed",
                "error": repr(e),
            })

    browser.stop()
    print("[playwright-orchestrator] Browser closed.")


if __name__ == "__main__":
    main()
