# defence/policy.py
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional
from urllib.parse import urlparse

import re


from .labels import Label, TaintSource


# Example: allow GitHub as "trusted-code-host"
TRUSTED_CODE_HOSTS = {
    "github.com",
    "gitlab.com",
    # add more if needed
}

# Domains that are always “untrusted context” (like your attack host)
EXPLICIT_UNTRUSTED_HOSTS = {
    "maliciousbook.com",
    "evilvideos.com",
    "darkwebforum.com",
    "shadytok.com",
    "suspiciouspins.com",
    "ilanbigio.com",
    "knotreeltest.github.io",
}


def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def classify_url(url: str) -> tuple[bool, str]:
    """
    Return (is_trusted, reason).
    """
    host = _hostname(url)
    if not host:
        return False, "no_host"

    if host in TRUSTED_CODE_HOSTS:
        return True, "trusted_code_host"

    if host in EXPLICIT_UNTRUSTED_HOSTS:
        return False, "explicit_untrusted_host"

    # Default stance: unknown web is untrusted but *tolerated* under taint
    return False, "unknown_web_host"


def taint_from_url(label: Label, url: str, src: TaintSource) -> Label:
    """
    Update a label given that some context came from a URL.
    """
    is_trusted, reason = classify_url(url)
    host = _hostname(url)

    new_label = Label(
        trusted=label.trusted,
        sources=set(label.sources),
        domains=set(label.domains),
        notes=set(label.notes),
    )

    if is_trusted:
        # We record the host but do not force untrusted
        new_label.add_domain(host)
        new_label.add_note(f"url:{host} classified as {reason}")
    else:
        # We “taint but allow continuation”
        new_label.taint(src, host, f"url:{host} classified as {reason}")

    return new_label


def taint_from_ocr_text(label: Label, text: str) -> Label:
    """
    OCR-based heuristic:
      1) Taint from full URLs (https://...).
      2) ALSO tain from bare hostnames like "github.io", "knotreeltest.github.io".
    """
    if not text:
        return label

    new_label = label

    # 1) Full URLs first
    url_re = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
    for u in url_re.findall(text):
        new_label = taint_from_url(new_label, u, TaintSource.OCR)

    # 2) Bare hostnames (no scheme) – e.g. "github.io", "knotreeltest.github.io"
    host_re = re.compile(
        r"\b([a-z0-9.-]+\.(?:io|com|net|org))\b",
        re.IGNORECASE,
    )
    for host in host_re.findall(text):
        host_l = host.lower()

        # We already handle github.com specially via TRUSTED_CODE_HOSTS.
        # For bare hosts, we synthesize a fake https:// URL to reuse taint_from_url.
        if host_l == "github.com":
            # Treat as trusted code host; this will record but not taint.
            fake_url = f"https://{host_l}"
            new_label = taint_from_url(new_label, fake_url, TaintSource.OCR)
        else:
            # Any other host (e.g. github.io, knotreeltest.github.io, etc.)
            fake_url = f"https://{host_l}"
            new_label = taint_from_url(new_label, fake_url, TaintSource.OCR)

    return new_label


class ActionClass(Enum):
    """
    Coarse FIDES-style “sink categories”.
    """
    NAVIGATION = auto()      # open URLs, click links, etc
    CODE_WRITE = auto()      # editing code / files
    EXTERNAL_POST = auto()   # posting comments, PRs, tickets
    SYSTEM_MUTATION = auto() # installs, config, etc
    READ_ONLY = auto()       # reading / analysis only


@dataclass
class ActionDecision:
    allow: bool
    warn: bool
    reason: str


def decide_action(label: Label, action: ActionClass, target_url: Optional[str] = None) -> ActionDecision:
    """
    “IFC taint-block” logic lives here.

    We do *not* kill the whole process on taint; instead, we:
      - Allow most READ_ONLY and NAVIGATION actions.
      - Restrict EXTERNAL_POST / CODE_WRITE when tainted by untrusted domains.
    """
    print(f"Deciding action {action}")
    # Clean context -> everything allowed
    if label.is_clean():
        return ActionDecision(True, False, "label_clean")

    # Optionally refine based on target URL
    target_host = _hostname(target_url) if target_url else None
    target_trusted, target_reason = (True, "no_target_url")
    if target_url:
        target_trusted, target_reason = classify_url(target_url)

    # If we’re tainted but only by trusted code hosts, be permissive
    if label.trusted is False and label.domains and all(
        h in TRUSTED_CODE_HOSTS for h in label.domains
    ):
        return ActionDecision(True, True, "tainted_by_trusted_code_hosts_only")

    # interesting cases: tainted by unknown / explicit untrusted hosts
    if action in (ActionClass.READ_ONLY, ActionClass.NAVIGATION):
        # Let the agent keep browsing / reading, but mark as risky
        return ActionDecision(True, True, "tainted_but_readonly_ok")

    if action in (ActionClass.CODE_WRITE, ActionClass.EXTERNAL_POST, ActionClass.SYSTEM_MUTATION):
        # Only allow if:
        #   - target is trusted, AND
        #   - EVERY taint domain is itself a trusted code host.
        if target_trusted and all(h in TRUSTED_CODE_HOSTS for h in label.domains):
            return ActionDecision(True, True, f"tainted_but_only_trusted_code_hosts:{target_reason}")

        # Otherwise block
        return ActionDecision(False, True, "tainted_block_sensitive_action")

    # Fallback: block conservatively
    return ActionDecision(False, True, "unhandled_action_class")


def classify_action(action: dict, state: dict) -> ActionClass:
    """
    Map raw CUA actions into IFC sink categories.
    Tune this mapping as your demo evolves.
    """
    action_type = (action.get("type") or "").lower()

    # --- Mouse stuff: mostly navigation ---
    if action_type in ("click", "move", "scroll", "drag", "screenshot", "wait"):
        return ActionClass.READ_ONLY if action_type in ("screenshot", "wait") else ActionClass.NAVIGATION

    # --- Keyboard shortcuts ---
    if action_type == "keypress":
        keys = {k.upper() for k in action.get("keys", [])}


        # Example: CTRL+ALT+T opens terminal -> high risk
        if keys == {"CTRL", "ALT", "T"}:
            return ActionClass.SYSTEM_MUTATION

        if keys == {"CTRL", "SHIFT", "V"}:
            # Pasting is a write sink (especially in terminal/editor)
            return ActionClass.CODE_WRITE

        # Other shortcuts – treat as navigation by default
        return ActionClass.NAVIGATION

    # --- Text typing ---
    if action_type == "type":
        text = (action.get("text") or "").strip()

        # 1) If it *looks* like a URL, treat it as navigation.
        #    This allows typing `github.com/knotreeltest/no-repo` even when tainted.
        if re.match(r"^(https?://)?[a-z0-9.-]+\.[a-z]{2,}(/.*)?$", text, re.IGNORECASE):
            return ActionClass.NAVIGATION

        # 2) If OCR suggests we’re in a browser, treat generic typing as navigation too.
        raw = (state.get("vision_raw_text") or "").lower()
        if any(browser in raw for browser in ("firefox", "chrome", "safari", "edge", "address and search bar")):
            return ActionClass.NAVIGATION

        # 3) If OCR suggests terminal / shell / editor, be strict.
        if any(term in raw for term in ("terminal", "bash", "zsh", "powershell", "cmd.exe", "visual studio code", "vscode")):
            return ActionClass.CODE_WRITE

        # 4) Fallback: treat as CODE_WRITE (conservative)
        return ActionClass.CODE_WRITE

    # Fallback: read-only
    return ActionClass.READ_ONLY
