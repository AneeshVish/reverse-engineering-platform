"""Deterministic plugin discovery.

Discovery works over explicitly-provided plugin candidates only — the built-in
reference plugins, or plugins a caller supplies. It performs no filesystem scanning
and no dynamic import. The discovered order is deterministic: plugins are returned
sorted by identifier, so the same candidate set always discovers in the same order.
"""

from __future__ import annotations

from collections.abc import Iterable

from .plugin import Plugin

__all__ = ["PluginDiscovery"]


class PluginDiscovery:
    """Deterministically orders a set of candidate plugins."""

    def discover(self, candidates: Iterable[Plugin]) -> tuple[Plugin, ...]:
        return tuple(sorted(candidates, key=lambda p: p.metadata().identifier))
