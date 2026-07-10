"""Engine construction helpers.

Convenience wiring for assembling a ready-to-use engine. There are no built-in
passes — analysis lives in later packages — so this only wires the registry,
pipeline, and manager together.
"""

from __future__ import annotations

from .config import PassEngineConfig, load_pass_engine_config
from .manager import PassEngineManager
from .pipeline import Pipeline
from .registry import PassRegistry

__all__ = ["build_engine"]


def build_engine(config: PassEngineConfig | None = None) -> PassEngineManager:
    """Construct a ``PassEngineManager`` with a fresh registry and pipeline."""

    resolved = config or load_pass_engine_config()
    return PassEngineManager(
        registry=PassRegistry(),
        pipeline=Pipeline(),
        config=resolved,
    )
