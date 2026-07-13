"""IR-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the IR-owned surface from the
``ir`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.ir]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["IRConfig", "load_ir_config", "IR_DEFAULTS"]

IR_DEFAULTS: dict[str, Any] = {
    # Whether builders validate structurally before returning a module (always
    # true in this phase; present so later phases can extend without a new
    # mechanism).
    "validate_on_build": True,
}


@dataclass
class IRConfig:
    """Typed view over IR-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(IR_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> IRConfig:
        merged: dict[str, Any] = dict(IR_DEFAULTS)
        sub = cfg.get("ir", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_ir_config(repo_root: Path | None = None) -> IRConfig:
    """Load IR configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return IRConfig.from_eng_config(load_config(root))
