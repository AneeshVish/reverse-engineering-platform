"""Knowledge-graph-owned configuration access.

Reuses the shared engineering loader (``reveng_config.load_config``) rather than
introducing a competing mechanism. Reads only the graph-owned surface from the
``graph`` sub-table of ``[tool.reveng]`` (i.e. ``[tool.reveng.graph]``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import EngConfig, load_config

__all__ = ["KnowledgeGraphConfig", "load_graph_config", "GRAPH_DEFAULTS"]

GRAPH_DEFAULTS: dict[str, Any] = {
    # Whether the builder validates the graph before returning it (always true in
    # this phase; present so later phases can extend without a new mechanism).
    "validate_on_build": True,
}


@dataclass
class KnowledgeGraphConfig:
    """Typed view over graph-owned configuration values."""

    values: dict[str, Any] = field(default_factory=lambda: dict(GRAPH_DEFAULTS))

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)

    @classmethod
    def from_eng_config(cls, cfg: EngConfig) -> KnowledgeGraphConfig:
        merged: dict[str, Any] = dict(GRAPH_DEFAULTS)
        sub = cfg.get("graph", {})
        if isinstance(sub, dict):
            merged.update(sub)
        return cls(values=merged)


def load_graph_config(repo_root: Path | None = None) -> KnowledgeGraphConfig:
    """Load graph configuration via the shared engineering loader."""

    root = repo_root or Path.cwd()
    return KnowledgeGraphConfig.from_eng_config(load_config(root))
