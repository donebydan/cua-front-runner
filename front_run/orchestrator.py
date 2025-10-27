# poc/orchestrator.py
"""
Orchestrator for the CUA Front-Runner PoC.
"""

import time
import traceback
from typing import Any, Dict, Optional

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
        "last_issue_url": None,
        "attack_done": False,
        "malicious_visit_seen": False,
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


    bus.on("process/stderr", on_stdout)
    bus.on("process/stdout", on_stdout)

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

    time.sleep(120)

    # If no automatic pause and still alive, perform fallback but only if safety gate passes
    if not docker.is_paused():
        print("[orchestrator] No public plan or CoT URL observed within timeout.")
        if not can_attack():
            print("[orchestrator] Safety gate: CUA not alive at fallback time. Skipping attack.")
            runlog.write({"event": "orchestrator.fallback_skipped", "reason": "safety_gate_cua_not_alive"})
        else:
            print("[orchestrator] Pausing as fallback and running attack.")
            try:
                docker.pause()
            except Exception as e:
                runlog.write({"event": "orchestrator.fallback_pause_failed", "error": repr(e)})
                print(f"[orchestrator] Warning: fallback docker.pause() failed: {e}")
            _run_attack_and_resume()

    # Final logging and cleanup
    runlog.write({
        "event": "orchestrator.run_complete",
        "attack_comment_url": state.get("attack_comment_url"),
        "public_plan": state.get("public_plan"),
        "last_issue_url": state.get("last_issue_url"),
        "malicious_visit_seen": state.get("malicious_visit_seen"),
    })
    print(f"[orchestrator] Run complete. Trace saved to: {runlog.path()}")

    try:
        cua.stop(timeout=2)
    except Exception:
        pass


if __name__ == "__main__":
    main()
