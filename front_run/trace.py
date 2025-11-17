import re
from typing import Optional
from .event_bus import EventBus
from .logger import RunLogger
import json


URL_RE = re.compile(r"https?://[^\s>]+", re.IGNORECASE)
PLAN_RE = re.compile(r"(?:PLAN|Public Plan|Next steps):\s*(.*)", re.IGNORECASE)
ACTION_RE = re.compile(r"(?:ACTION|Tool|Click|Navigate):\s*(.*)", re.IGNORECASE)


ACTION_START = "        \"action\": {"

class Trace:
    def __init__(self, bus: EventBus, logger: RunLogger, malicious_host: str):
        self.bus = bus
        self.logger = logger
        self.malicious_host = malicious_host
        self.last_seen_issue_url: Optional[str] = None
        self._accum_action = None
        self._handler = self._on_stdout
        
        self.bus.on("process/stdout", self._on_stdout)

    def _on_stdout(self, evt):
        line: str = evt.payload["line"]

        # existing URL / plan / action detection ...
        for m in URL_RE.finditer(line):
            url = m.group(0)
            #self.logger.write({"event": "url_seen", "url": url})
            if "/issues/" in url:
                self.last_seen_issue_url = url
                self.bus.emit("trace/issue_url", url=url)

        if ACTION_START in line:
            self._accum_action = "{"
            return

        if self._accum_action is not None:
            if line.strip() == "},":
                # completed action JSON
                self._accum_action += "}"
                try:
                    action_obj = json.loads(self._accum_action)
                    self.logger.write({"event": "action", "text": json.dumps(action_obj)})
                    self.bus.emit("trace/action", text=json.dumps(action_obj))
                except Exception as e:
                    self.logger.write({"event": "action_parse_error", "error": repr(e), "text": self._accum_action})
                self._accum_action = None
            else:
                self._accum_action += line.strip()
            return
    

    def unregister(self):
        # remove subscription (useful in tests / teardown)
        try:
            self.bus.off("process/stdout", self._handler)
        except Exception:
            pass
