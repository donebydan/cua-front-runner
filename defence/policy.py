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
    Example OCR-based heuristic: if we see non-whitelisted domains in text,
    treat them as taint sources - but keep Github etc. as trusted.
    """
    # TODO we can plug a better URL extractor here..
    url_re = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
    urls = url_re.findall(text or "")

    new_label = label
    for u in urls:
        new_label = taint_from_url(new_label, u, TaintSource.OCR)

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
        # Only allow if target is clearly trusted AND we’re not tainted by explicit bad hosts
        if target_trusted and not (label.domains & EXPLICIT_UNTRUSTED_HOSTS):
            return ActionDecision(True, True, f"tainted_but_target_trusted:{target_reason}")
        # Otherwise block
        return ActionDecision(False, True, "tainted_block_sensitive_action")

    # Fallback: block conservatively
    return ActionDecision(False, True, "unhandled_action_class")
