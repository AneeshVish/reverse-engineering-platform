"""Plugin-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the plugin-owned surface from the
``plugins`` sub-table of ``[tool.reveng]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["PluginConfig", "load_plugin_config", "PLUGIN_DEFAULTS"]

PLUGIN_DEFAULTS: dict[str, Any] = {
    # Whether the manager registers the built-in reference plugins on init
    # (always true in this phase; present so later phases can extend behavior).
    "load_reference_plugins": True,
}


@dataclass
class PluginConfig:
    """Typed view over plugin-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(PLUGIN_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> PluginConfig:
        merged: dict[str, Any] = dict(PLUGIN_DEFAULTS)
        sub = cfg.get("plugins", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_plugin_config(repo_root: Path | None = None) -> PluginConfig:
    """Load plugin configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return PluginConfig.from_eng_config(load_config(root))
