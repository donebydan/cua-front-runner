# defence/labels.py
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Set, Optional


class TaintSource(Enum):
    NONE = auto()
    # fine-grained like FIDES sources
    SCREENSHOT = auto()
    OCR = auto()
    DOM = auto()
    OFFSCREEN = auto()
    NETWORK = auto()


@dataclass
class Label:
    """
    Extremely simple IFC label for the demo.

    - trusted: if False, we treat this context as untrusted / tainted.
    - sources: where taint came from.
    - domains: which external domains were involved (github.com, evil.com, etc).
    - notes: free-form hints for logging / debugging.
    """
    trusted: bool = True
    sources: Set[TaintSource] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    notes: Set[str] = field(default_factory=set)

    def is_clean(self) -> bool:
        return self.trusted and not self.sources and not self.domains

    def add_source(self, src: TaintSource) -> None:
        if src != TaintSource.NONE:
            self.sources.add(src)

    def add_domain(self, domain: str) -> None:
        if domain:
            self.domains.add(domain)

    def add_note(self, note: str) -> None:
        if note:
            self.notes.add(note)

    def taint(self, src: TaintSource, domain: Optional[str] = None, note: str = "") -> None:
        self.trusted = False
        self.add_source(src)
        if domain:
            self.add_domain(domain)
        if note:
            self.add_note(note)


def merge_labels(a: Label, b: Label) -> Label:
    """
    Join operator like in FIDES: result is the "more restrictive" label.
    """
    return Label(
        trusted=a.trusted and b.trusted,
        sources=a.sources | b.sources,
        domains=a.domains | b.domains,
        notes=a.notes | b.notes,
    )


# A default “clean” label for initial state
CLEAN_LABEL = Label()
