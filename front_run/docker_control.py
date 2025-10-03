import docker
from .config import settings


class DockerControl:
    def __init__(self, container_name: str = None):
        self.client = docker.from_env()
        self.name = container_name or settings.container_name

    def _container(self):
        return self.client.containers.get(self.name)

    def pause(self):
        self._container().pause()

    def unpause(self):
        self._container().unpause()

    def is_running(self) -> bool:
        try:
            c = self._container()
            return c.status in {"running", "paused"}
        except Exception:
            return False

    def is_paused(self) -> bool:
        try:
            return self._container().status == "paused"
        except Exception:
            return False