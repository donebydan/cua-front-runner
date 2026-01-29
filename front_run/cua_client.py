import subprocess
import threading
import sys
import time
from pathlib import Path
from typing import Optional


from .config import settings
from .event_bus import EventBus


class CUAClient:
    """Runs the sample app CLI and streams stdout lines into the EventBus.
    We send the task to stdin after the UI comes up.
    """

    def __init__(self, bus: EventBus, cli_path: Optional[str] = None):
        self.bus = bus
        self.cli_path = cli_path or settings.cli_path
        self.proc: Optional[subprocess.Popen] = None
        self._reader_thread: Optional[threading.Thread] = None


    def start(self):
        cmd = [sys.executable, self.cli_path, "--computer", "docker", "--debug"]
        print(cmd)
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader_thread.start()


    def _read_stdout(self):
        assert self.proc and self.proc.stdout
        # for line in self.proc.stdout:
        #     line = line.rstrip("\n")
        #     self.bus.emit("process/stdout", line=line)
        # self.bus.emit("process/exit", code=self.proc.poll())
        try:
            for line in self.proc.stdout:
                line = line.rstrip("\n")
                self.bus.emit("process/stdout", line=line)
        except Exception as e:
            self.bus.emit("process/stdout_error", error=repr(e))
        finally:
            try:
                code = self.proc.poll()
            except Exception:
                code = None
            self.bus.emit("process/exit", code=code)


    def send_task(self, repo_full_name: str):
        assert self.proc and self.proc.stdin
        prompt = settings.task_prompt.format(repo=repo_full_name)
        self.bus.emit("process/stdin", text=prompt)
        self.proc.stdin.write(prompt + "\n")
        self.proc.stdin.flush()


    def stop(self, timeout=5):
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=timeout)
        except Exception:
            self.proc.kill()


    def wait(self, seconds: int):
        time.sleep(seconds)