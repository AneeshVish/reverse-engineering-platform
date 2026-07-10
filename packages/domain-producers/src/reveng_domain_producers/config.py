"""Producer-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the producer-owned surface from the
``producers`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.producers]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["ProducerConfig", "load_producer_config", "PRODUCER_DEFAULTS"]

PRODUCER_DEFAULTS: dict[str, Any] = {
    # Whether the raw-binary fallback producer is enabled (always true here;
    # present so later phases can toggle it without a new config mechanism).
    "enable_raw_fallback": True,
}


@dataclass
class ProducerConfig:
    """Typed view over producer-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(PRODUCER_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> ProducerConfig:
        merged: dict[str, Any] = dict(PRODUCER_DEFAULTS)
        sub = cfg.get("producers", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_producer_config(repo_root: Path | None = None) -> ProducerConfig:
    """Load producer configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return ProducerConfig.from_eng_config(load_config(root))
