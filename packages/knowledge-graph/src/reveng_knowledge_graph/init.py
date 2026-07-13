"""Construction helper for the knowledge-graph manager."""

from __future__ import annotations

from .config import KnowledgeGraphConfig, load_graph_config
from .manager import KnowledgeGraphManager

__all__ = ["build_knowledge_graph"]


def build_knowledge_graph(config: KnowledgeGraphConfig | None = None) -> KnowledgeGraphManager:
    """Construct a ``KnowledgeGraphManager`` with resolved configuration."""

    return KnowledgeGraphManager(config=config or load_graph_config())
