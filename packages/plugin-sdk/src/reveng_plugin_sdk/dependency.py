"""Deterministic plugin dependency resolution.

Given a set of plugins, produce a load order in which every plugin appears after
its declared dependencies. The topological sort is deterministic: among plugins
whose dependencies are already satisfied, the earliest-registered (by input order)
is chosen first. Missing dependencies and cycles are reported as ``DependencyError``.
"""

from __future__ import annotations

from collections.abc import Sequence

from .errors import DependencyError
from .plugin import Plugin

__all__ = ["resolve_load_order", "DependencyResolver"]


def resolve_load_order(plugins: Sequence[Plugin]) -> tuple[str, ...]:
    """Return plugin identifiers in dependency order (deps before dependents)."""

    index = {p.metadata().identifier: i for i, p in enumerate(plugins)}
    deps: dict[str, tuple[str, ...]] = {}
    for plugin in plugins:
        meta = plugin.metadata()
        for dep in meta.dependencies:
            if dep not in index:
                raise DependencyError(
                    "missing plugin dependency", plugin=meta.identifier, dependency=dep
                )
        deps[meta.identifier] = tuple(meta.dependencies)

    remaining = set(deps)
    ordered: list[str] = []
    while remaining:
        ready = sorted(
            (pid for pid in remaining if all(d in ordered for d in deps[pid])),
            key=lambda pid: index[pid],
        )
        if not ready:
            raise DependencyError(
                "plugin dependency cycle",
                unresolved=tuple(sorted(remaining, key=lambda pid: index[pid])),
            )
        for pid in ready:
            ordered.append(pid)
            remaining.discard(pid)
    return tuple(ordered)


class DependencyResolver:
    """Object wrapper around :func:`resolve_load_order`."""

    def resolve(self, plugins: Sequence[Plugin]) -> tuple[str, ...]:
        return resolve_load_order(plugins)
