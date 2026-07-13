"""Reasoning-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the reasoning-owned surface from the
``reasoning`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.reasoning]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["ReasoningConfig", "load_reasoning_config", "REASONING_DEFAULTS"]

REASONING_DEFAULTS: dict[str, Any] = {
    # Symbol names treated as module entry points by the missing-entry rule.
    "entry_symbols": ("main", "_start", "start"),
}


@dataclass
class ReasoningConfig:
    """Typed view over reasoning-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(REASONING_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    def entry_symbols(self) -> tuple[str, ...]:
        raw = self.values.get("entry_symbols", ())
        if isinstance(raw, (list, tuple)):
            return tuple(str(x) for x in raw)
        if isinstance(raw, str):
            return (raw,)
        return ()

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> ReasoningConfig:
        merged: dict[str, Any] = dict(REASONING_DEFAULTS)
        sub = cfg.get("reasoning", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_reasoning_config(repo_root: Path | None = None) -> ReasoningConfig:
    """Load reasoning configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return ReasoningConfig.from_eng_config(load_config(root))
