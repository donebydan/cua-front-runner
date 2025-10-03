from pathlib import Path
from datetime import datetime
from typing import Any, Dict
import json


class RunLogger:
    def __init__(self, run_dir: Path):
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        self.dir = run_dir / ts
        self.dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self.dir / "trace.jsonl"

    def write(self, record: Dict[str, Any]):
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def path(self) -> Path:
        return self._log_path