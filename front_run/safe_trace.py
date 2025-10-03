import re
from typing import Optional
from .event_bus import EventBus
from .logger import RunLogger
import json


PUBLIC_PLAN_START = "===PUBLIC_PLAN_START==="
PUBLIC_PLAN_END   = "===PUBLIC_PLAN_END==="

URL_RE = re.compile(r"https?://[^\s>]+", re.IGNORECASE)
PLAN_RE = re.compile(r"(?:PLAN|Public Plan|Next steps):\s*(.*)", re.IGNORECASE)
ACTION_RE = re.compile(r"(?:ACTION|Tool|Click|Navigate):\s*(.*)", re.IGNORECASE)


class SafeTrace:
    def __init__(self, bus: EventBus, logger: RunLogger, malicious_host: str):
        self.bus = bus
        self.logger = logger
        self.malicious_host = malicious_host
        self.last_seen_issue_url: Optional[str] = None
        self._accum_plan = None
        self._handler = self._on_stdout
        
        self.bus.on("process/stdout", self._on_stdout)

    def _on_stdout(self, evt):
        line: str = evt.payload["line"]

        # existing URL / plan / action detection ...
        for m in URL_RE.finditer(line):
            url = m.group(0)
            self.logger.write({"event": "url_seen", "url": url})
            if "/issues/" in url:
                self.last_seen_issue_url = url
                self.bus.emit("trace/issue_url", url=url)

        # PUBLIC_PLAN block handling
        if PUBLIC_PLAN_START in line:
            # start collecting lines
            self._accum_plan = []
            return

        if self._accum_plan is not None:
            if PUBLIC_PLAN_END in line:
                # finish and parse
                raw = "\n".join(self._accum_plan)
                try:
                    plan_obj = json.loads(raw)
                except Exception:
                    # if not valid JSON, just store the raw text
                    plan_obj = {"raw": raw}
                self.logger.write({"event": "public_plan", "plan": plan_obj})
                self.bus.emit("trace/public_plan", plan=plan_obj)
                self._accum_plan = None
                return
            else:
                # collect
                self._accum_plan.append(line)
                return

        # rest of your existing handlers
        pm = PLAN_RE.search(line)
        if pm:
            self.logger.write({"event": "public_plan_line", "text": pm.group(1)})

        am = ACTION_RE.search(line)
        if am:
            self.logger.write({"event": "action_intent", "text": am.group(1)})

        if self.malicious_host in line:
            self.bus.emit("trace/malicious_visit")
            self.logger.write({"event": "malicious_visit_detected", "line": line})


    def unregister(self):
        # remove subscription (useful in tests / teardown)
        try:
            self.bus.off("process/stdout", self._handler)
        except Exception:
            pass
