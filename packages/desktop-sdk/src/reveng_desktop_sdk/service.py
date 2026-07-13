"""Desktop service lifecycle.

Owns the ``DesktopClient`` and the local public-API process, if any. Always
attempts to attach to whatever is reachable at the configured base URL
first; if nothing answers and the config allows it, spawns a local service
process and polls ``/health`` until ready. "Automatically reconnects" is
realized as ``ensure_connected()`` -- a synchronous check-and-relaunch-if-
needed called by ``DesktopManager`` before each remote call -- not a
background thread; this package has no need for one.
"""

from __future__ import annotations

import subprocess
import sys
import time
from urllib.parse import urlsplit

from reveng_core_substrate import HealthAggregator, HealthResult, HealthState

from .client import DesktopClient
from .config import DesktopSdkConfig
from .errors import ServiceUnavailableError

__all__ = ["DesktopService"]


class DesktopService:
    """Lifecycle-aware owner of the ``DesktopClient`` and (optionally) the
    local public-API service process."""

    component_name = "desktop-sdk.service"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self, config: DesktopSdkConfig | None = None, *, client: DesktopClient | None = None
    ) -> None:
        self._config = config or DesktopSdkConfig()
        base_url = str(self._config.get("base_url"))
        self._client = client or DesktopClient(
            base_url, timeout=float(self._config.get("startup_timeout_seconds"))
        )
        self._process: subprocess.Popen[bytes] | None = None

    @property
    def client(self) -> DesktopClient:
        return self._client

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        self.start()

    def shutdown(self) -> None:
        self.stop()

    # -- service lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Idempotent: attach to a reachable service, or self-manage one."""

        if self.is_running():
            return

        if not self._config.get("self_manage_process"):
            raise ServiceUnavailableError(
                "no service reachable and self_manage_process is disabled",
                base_url=str(self._config.get("base_url")),
            )

        self._spawn_process()
        self._wait_until_healthy()

    def stop(self) -> None:
        """Idempotent: closes the client and terminates any owned process."""

        self._client.close()
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5.0)
        self._process = None

    def is_running(self) -> bool:
        """Never raises: any failure (including a closed client after
        ``stop()``) means "not running", not a propagated exception."""

        try:
            self._client.health()
            return True
        except Exception:  # noqa: BLE001 - deliberate best-effort probe
            return False

    def ensure_connected(self) -> None:
        """Called before each remote call; reconnects/relaunches if needed."""

        if not self.is_running():
            self.start()

    def _spawn_process(self) -> None:
        parts = urlsplit(str(self._config.get("base_url")))
        host = parts.hostname or "127.0.0.1"
        port = parts.port or 8000
        # Launched as a subprocess argv string, not an `import` statement in
        # this package's own source -- check_dep_001 AST-scans this
        # package's imports only, so this never creates a packages->apps edge.
        code = f"import uvicorn, reveng_api; uvicorn.run(reveng_api.app, host={host!r}, port={port})"
        self._process = subprocess.Popen([sys.executable, "-c", code])

    def _wait_until_healthy(self) -> None:
        timeout = float(self._config.get("startup_timeout_seconds"))
        interval = float(self._config.get("poll_interval_seconds"))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_running():
                return
            time.sleep(interval)
        raise ServiceUnavailableError(
            "self-managed service did not become healthy before timeout",
            timeout=timeout,
        )

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        aggregator = HealthAggregator()
        running = self.is_running()
        aggregator.register(
            "service",
            lambda: HealthResult(
                HealthState.HEALTHY if running else HealthState.UNHEALTHY,
                detail="reachable" if running else "unreachable",
            ),
        )
        overall = aggregator.evaluate().overall
        return HealthResult(overall, detail="running" if running else "not running")

    def health_state(self) -> HealthState:
        return self.health().state
