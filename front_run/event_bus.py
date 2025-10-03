from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass
class Event:
    type: str
    payload: Dict[str, Any]


class EventBus:
    def __init__(self):
        self._subs: Dict[str, List[Callable[[Event], None]]] = {}


    def on(self, event_type: str, handler: Callable[[Event], None]):
        self._subs.setdefault(event_type, []).append(handler)


    def emit(self, event_type: str, **payload):
        for h in self._subs.get(event_type, []):
            h(Event(event_type, payload))


    def off(self, event_type: str, handler: Callable[[Event], None]):
        handlers = self._subs.get(event_type)
        if not handlers:
            return
        try:
            handlers.remove(handler)
        except ValueError:
            pass
        if not handlers:
            self._subs.pop(event_type, None)