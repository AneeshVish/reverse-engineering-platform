"""Pass-engine configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the engine-owned surface from the
``pass_engine`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.pass_engine]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["PassEngineConfig", "load_pass_engine_config", "PASS_ENGINE_DEFAULTS"]

PASS_ENGINE_DEFAULTS: dict[str, Any] = {
    # Whether a failed pass skips its dependents (always true in this phase;
    # present so later phases can extend behavior without a new mechanism).
    "skip_dependents_on_failure": True,
}


@dataclass
class PassEngineConfig:
    """Typed view over engine-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(PASS_ENGINE_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> PassEngineConfig:
        merged: dict[str, Any] = dict(PASS_ENGINE_DEFAULTS)
        sub = cfg.get("pass_engine", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_pass_engine_config(repo_root: Path | None = None) -> PassEngineConfig:
    """Load engine configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return PassEngineConfig.from_eng_config(load_config(root))
