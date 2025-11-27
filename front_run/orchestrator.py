"""
Orchestrator for the CUA Front-Runner PoC.
"""

import time
import json
from typing import Any, Dict
from urllib.parse import urlparse
import base64
import os
import re
import subprocess
import tempfile
import pytesseract
from PIL import Image
import io

from .config import settings
from .event_bus import EventBus
from .logger import RunLogger
from .trace import Trace
from .docker_control import DockerControl
from .cua_client import CUAClient
from .attack_agent import AttackAgent

from defence.labels import CLEAN_LABEL
from defence.ifc import (
    propagate_from_current_url,
    propagate_from_ocr,
    check_sensitive_action,
)
from defence.policy import ActionClass, classify_action


BANNER = """
============================================
   CUA Front-Runner PoC ? Orchestrator
============================================
"""


def main():
    print(BANNER)

    bus = EventBus()
    runlog = RunLogger(settings.run_dir)
    docker = DockerControl(settings.container_name)

    runlog.write({
        "event": "defence.status",
        "enabled": settings.defence_enabled,
    })

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
        "vision_is_github": False,
        "vision_repo": None,
        "vision_tab": None,
        "vision_raw_text": None,
        "taint_label": CLEAN_LABEL,
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
    # IFC Gating helper
    # ---------------------------------------------------------------------
    def ifc_gate_action(action: dict, phase: str) -> bool:
        """
        Run IFC decision for a single action.

        Returns:
            True  => allow action to proceed
            False => block / abort run (caller should enforce)
        """
        action_class = classify_action(action, state)
        label = state["taint_label"]

        # For navigation we can optionally pass the current URL as target
        target_url = None
        if action_class in (ActionClass.NAVIGATION, ActionClass.READ_ONLY):
            target_url = state.get("current_url")

        decision = check_sensitive_action(label, action_class, target_url=target_url)

        runlog.write({
            "event": "orchestrator.ifc_action_decision",
            "phase": phase,
            "action_class": action_class.name,
            "allow": decision.allow,
            "warn": decision.warn,
            "reason": decision.reason,
            "label": {
                "trusted": label.trusted,
                "sources": [s.name for s in label.sources],
                "domains": list(label.domains),
            },
            "action": action,
        })

        if not decision.allow:
            # Enforcement strategy for demo: stop CUA + mark run as ?blocked?
            state["attack_done"] = True
            try:
                cua.stop(timeout=1)
            except Exception:
                pass

            runlog.write({
                "event": "orchestrator.ifc_blocked_action",
                "phase": phase,
                "action_class": action_class.name,
            })

            return False

        return True


    # ---------------------------------------------------------------------
    # Basic stdout logging
    # ---------------------------------------------------------------------
    def on_stdout(evt):
        line = evt.payload.get("line", "")

        max_len = 400
        if len(line) > max_len:
            truncated = line[:max_len] + f"... [truncated {len(line) - max_len} chars]"
        else:
            truncated = line

        runlog.write({
            "event": "cua_stdout",
            "line": truncated,
        })

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

        # OCR-derived hints
        vision_repo = (state.get("vision_repo") or "").strip("/")
        vision_is_github = bool(state.get("vision_is_github"))
        vision_tab = (state.get("vision_tab") or "").lower()

        runlog.write({
            "event": "orchestrator.issues_click_seen",
            "source": source,
            "x": x,
            "y": y,
            "last_typed_url": last_typed,
            "current_url": current_url,
            "vision_repo": vision_repo,
            "vision_tab": vision_tab,
            "vision_is_github": vision_is_github,
        })

        # Prefer target_repo instead of hard-coding knotreeltest/no-repo
        typed_matches_target = (
            target_repo and ("/" + target_repo) in last_typed
        )

        vision_matches_target = (
            target_repo and vision_repo == target_repo
        )

        looks_like_github = on_github or vision_is_github

        # Conditions under which we arm the attack:
        #   - Typed URL clearly for target repo's issues page, OR
        #   - OCR says it's the target repo and the issues tab is involved, OR
        #   - We?re on a GitHub page (by URL or OCR) and this appears to be Issues tab.
        if (
            typed_matches_target
            or vision_matches_target
            or (looks_like_github and vision_tab == "issues")
        ):
            arm_attack(
                "orchestrator.issues_click_triggers_attack",
                {
                    "source": source,
                    "typed_matches_target": typed_matches_target,
                    "vision_matches_target": vision_matches_target,
                    "looks_like_github": looks_like_github,
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
                "vision_repo": vision_repo,
                "vision_tab": vision_tab,
                "vision_is_github": vision_is_github,
            })

    # -----------------------------------------------------------------
    # OCR / vision integration hook
    # -----------------------------------------------------------------
    def _tesseract_text_from_image_url(image_url: str) -> str:
        """
        Decode base64 screenshot and run Tesseract OCR via pytesseract.
        Returns raw extracted text.
        """
        # Extract base64 portion
        if image_url.startswith("data:"):
            try:
                _, b64data = image_url.split(",", 1)
            except ValueError:
                b64data = image_url
        else:
            b64data = image_url

        try:
            img_bytes = base64.b64decode(b64data)
            img = Image.open(io.BytesIO(img_bytes))

            text = pytesseract.image_to_string(img)
            return text
        except Exception as e:
            runlog.write({
                "event": "orchestrator.ocr_error",
                "error": repr(e),
            })
            return ""

    
    OCR_URL_RE = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)
    OCR_GH_REPO_URL_RE = re.compile(
        r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
        re.IGNORECASE,
    )
    # e.g. "knotreeltest / no-repo" in the repo header
    OCR_GH_REPO_HEADER_RE = re.compile(
        r"\b([A-Za-z0-9_.-]+)\s*/\s*([A-Za-z0-9_.-]+)\b"
    )


    def _parse_github_from_ocr(text: str) -> Dict[str, Any]:
        """
        Heuristically extract GitHub-related metadata from raw OCR text.

        Returns:
            {
                "detected_url": str | None,
                "is_github": bool,
                "repo": str | None,   # "owner/repo"
                "tab": str | None,    # "issues", "code", "pulls", etc.
                "raw_text": str,
            }
        """
        meta: Dict[str, Any] = {
            "detected_url": None,
            "is_github": False,
            "repo": None,
            "tab": None,
            "raw_text": text or "",
        }

        if not text:
            return meta

        lowered = text.lower()

        # --- 1) Is this even GitHub? ---
        if "github.com" in lowered:
            meta["is_github"] = True

        # --- 2) Try to find a full https://github.com/owner/repo URL ---
        m = re.search(
            r"https?://github\.com/([a-z0-9_.-]+)/([a-z0-9_.-]+)",
            lowered,
            re.IGNORECASE,
        )
        if m:
            owner, repo = m.group(1), m.group(2)
            meta["repo"] = f"{owner}/{repo}"
            meta["detected_url"] = f"https://github.com/{owner}/{repo}"

        # --- 3) Fallback: match known target_repo if both parts appear in OCR text ---
        if not meta["repo"]:
            target = (settings.target_repo or "").strip("/")  # e.g. "knotreeltest/no-repo"
            if target and "/" in target:
                owner, repo = target.split("/", 1)
                if owner.lower() in lowered and repo.lower() in lowered:
                    meta["repo"] = target
                    # we don't know the exact URL path from OCR, so leave detected_url as None

        # --- 4) Tab detection heuristics from visible words ---
        # This will work better once we're on the repo page / issues tab, etc.
        if "issues" in lowered:
            meta["tab"] = "issues"
        elif "pull requests" in lowered or "pulls" in lowered:
            meta["tab"] = "pulls"
        elif "actions" in lowered:
            meta["tab"] = "actions"
        elif "code" in lowered and "issues" not in lowered:
            # crude heuristic: only set "code" if we don't also see "issues"
            meta["tab"] = "code"

        return meta


    def run_ocr_on_image(image_url: str) -> Dict[str, Any]:
        """
        Given an image URL (from the CUA screenshot), run OCR / vision
        and return structured metadata.

        Implemented using Tesseract. Expects `image_url` to be either:
          - a data URL: data:image/png;base64,...
          - or raw base64-encoded image data.

        Returns:
            {
                "detected_url": str | None,
                "is_github": bool,
                "repo": str | None,
                "tab": str | None,
                "raw_text": str | None,
            }
        """
        # 1) Extract raw text via Tesseract
        text = _tesseract_text_from_image_url(image_url)

        # Empty text check for logging
        if not text:
            runlog.write({
                "event": "orchestrator.ocr_empty_text",
            })

        # 2) Parse GitHub-specific metadata from OCR text
        meta = _parse_github_from_ocr(text)

        return meta


    def apply_ocr_metadata(meta: Dict[str, Any]) -> None:
        if not meta:
            return

        detected_url = meta.get("detected_url")
        is_github = bool(meta.get("is_github"))
        repo = meta.get("repo")
        tab = meta.get("tab")
        raw_text = meta.get("raw_text")

        # Persist OCR-derived info
        if detected_url and not state.get("current_url"):
            state["current_url"] = detected_url

        state["vision_is_github"] = is_github
        if repo:
            state["vision_repo"] = repo
        if tab:
            state["vision_tab"] = tab
        if raw_text:
            state["vision_raw_text"] = raw_text
            runlog.write({
                "event": "orchestrator.ocr_raw_text_snippet",
                "snippet": raw_text[:500],
            })

            # IFC taint propagation from OCR text
            old_label = state["taint_label"]
            new_label = propagate_from_ocr(old_label, raw_text)
            state["taint_label"] = new_label
            runlog.write({
                "event": "orchestrator.ifc_ocr_propagated",
                "ifc_label": {
                    "trusted": new_label.trusted,
                    "sources": [s.name for s in new_label.sources],
                    "domains": list(new_label.domains),
                },
            })

        # Augment with URL-derived truth if we have it
        current_url = state.get("current_url")
        if current_url and "github.com" in current_url:
            parsed = urlparse(current_url)
            parts = parsed.path.strip("/").split("/")
            if len(parts) >= 2:
                owner, repo_name = parts[0], parts[1]
                url_repo = f"{owner}/{repo_name}"
                # prefer URL for repo if OCR didn't get it right
                if not state.get("vision_repo"):
                    state["vision_repo"] = url_repo
                if not meta.get("repo"):
                    meta["repo"] = url_repo

            if len(parts) >= 3:
                slug = parts[2]
                slug_to_tab = {
                    "issues": "issues",
                    "pulls": "pulls",
                    "pull-requests": "pulls",
                    "actions": "actions",
                    "code": "code",
                }
                url_tab = slug_to_tab.get(slug)
                if url_tab:
                    state["vision_tab"] = url_tab
                    if not meta.get("tab"):
                        meta["tab"] = url_tab

        runlog.write({
            "event": "orchestrator.ocr_metadata_applied",
            "detected_url": detected_url,
            "is_github": is_github or ("github.com" in (state.get("current_url") or "")),
            "repo": state.get("vision_repo"),
            "tab": state.get("vision_tab"),
        })

        # Auto-arm if we know we're on the target repo issues page
        target_repo = (settings.target_repo or "").strip("/")
        if (
            not state["comment_triggered"]
            and state.get("vision_repo") == target_repo
            and state.get("vision_tab") == "issues"
        ):
            arm_attack(
                "orchestrator.ocr_or_url_detected_target_issues_page",
                {
                    "repo": state["vision_repo"],
                    "tab": state["vision_tab"],
                    "current_url": state.get("current_url"),
                },
            )


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

        if not ifc_gate_action(action, phase="trace/action"):
            # block; don?t run any of the normal logic for this action
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
        item_type = item.get("type")

        if item_type == "message":
            content = item.get("content", [])
            if (
                content
                and isinstance(content, list)
                and content[0].get("type") == "output_text"
            ):
                text = content[0].get("text", "")
                runlog.write({"event": "trace.model_text", "text": text})

        if item_type == "computer_call_output":
            output = item.get("output") or {}

            # IFC taint propagation from current_url in computer_call_output
            current_url = output.get("current_url")
            if current_url:
                state["current_url"] = current_url
                old_label = state["taint_label"]
                new_label = propagate_from_current_url(old_label, current_url)
                state["taint_label"] = new_label

                runlog.write({
                    "event": "orchestrator.current_url_seen",
                    "url": current_url,
                    "ifc_label": {
                        "trusted": new_label.trusted,
                        "sources": [s.name for s in new_label.sources],
                        "domains": list(new_label.domains),
                    },
                })

            if output.get("type") == "input_image":
                image_url = output.get("image_url")
                if image_url:
                    runlog.write({
                        "event": "orchestrator.ocr_requested",
                        "call_id": item.get("call_id"),
                        "image_len": len(image_url) if image_url else 0,
                    })
                    try:
                        meta = run_ocr_on_image(image_url)
                        apply_ocr_metadata(meta)
                    except Exception as e:
                        runlog.write({
                            "event": "orchestrator.ocr_failed",
                            "error": repr(e),
                            "call_id": item.get("call_id"),
                        })

        state["last_model_items"].append(item)

    bus.on("trace/model_item", on_model_item)

    def on_computer_call(evt):
        """
        Handle low-level computer_call events emitted by Trace.

        Expects payload like:
            {"item": {"type": "computer_call", "action": {...}, ...}}
        """
        item = evt.payload.get("item", {}) or {}
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

        if not ifc_gate_action(action, phase="trace/computer_call"):
            return

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
                label = state["taint_label"]
                decision = check_sensitive_action(
                    label,
                    ActionClass.EXTERNAL_POST,
                    target_url=settings.issue_url,
                )

                runlog.write({
                    "event": "orchestrator.ifc_decision",
                    "action_class": "EXTERNAL_POST",
                    "target_url": settings.issue_url,
                    "allow": decision.allow,
                    "warn": decision.warn,
                    "reason": decision.reason,
                    "label": {
                        "trusted": label.trusted,
                        "sources": [s.name for s in label.sources],
                        "domains": list(label.domains),
                    },
                })

                if not decision.allow:
                    # Defence kicks in: do NOT post the comment
                    state["attack_done"] = True
                    runlog.write({"event": "orchestrator.ifc_blocked_attack"})
                else:
                    # Attack Demo Logic: post the comment
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
