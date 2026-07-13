"""Desktop-SDK-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather
than introducing a competing mechanism. Reads only the desktop-sdk-owned
surface from the ``desktop_sdk`` sub-table of ``[tool.reveng]``.

Infra knobs only: how to reach/manage the public API service. Nothing here
concerns UI-adjacent state (that lives in ``preferences.py``/``workspace.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["DesktopSdkConfig", "load_desktop_sdk_config", "DESKTOP_SDK_DEFAULTS"]

DESKTOP_SDK_DEFAULTS: dict[str, Any] = {
    "base_url": "http://127.0.0.1:8000",
    # Whether DesktopService may spawn a local service process when none is
    # reachable at base_url.
    "self_manage_process": False,
    "startup_timeout_seconds": 15.0,
    "poll_interval_seconds": 0.5,
}


@dataclass
class DesktopSdkConfig:
    """Typed view over desktop-sdk-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(DESKTOP_SDK_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> DesktopSdkConfig:
        merged: dict[str, Any] = dict(DESKTOP_SDK_DEFAULTS)
        sub = cfg.get("desktop_sdk", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_desktop_sdk_config(repo_root: Path | None = None) -> DesktopSdkConfig:
    """Load desktop-sdk configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return DesktopSdkConfig.from_eng_config(load_config(root))
