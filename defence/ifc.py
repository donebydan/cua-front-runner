# defence/ifc.py
from typing import Optional

from front_run.config import settings
from .labels import Label, TaintSource, merge_labels
from .policy import taint_from_url, taint_from_ocr_text, decide_action, ActionClass, ActionDecision


def propagate_from_current_url(label: Label, url: Optional[str]) -> Label:
    if not settings.defence_enabled:
        return label
    
    if not url:
        return label
    return taint_from_url(label, url, TaintSource.NETWORK)


def propagate_from_ocr(label: Label, ocr_text: Optional[str]) -> Label:
    if not settings.defence_enabled:
        return label
    
    if not ocr_text:
        return label
    return taint_from_ocr_text(label, ocr_text)


def combine(label_a: Label, label_b: Label) -> Label:
    return merge_labels(label_a, label_b)


def check_sensitive_action(
    label: Label,
    action_class: ActionClass,
    target_url: Optional[str] = None,
) -> ActionDecision:
    """
    Simple wrapper so orchestrator doesn’t depend directly on policy internals.
    """
    if not settings.defence_enabled:
        # Defence disabled: allow everything, but record why.
        return ActionDecision(
            allow=True,
            warn=False,
            reason="defence_disabled",
        )

    return decide_action(label, action_class, target_url)