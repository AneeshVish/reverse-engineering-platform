"""Execution planning.

Builds a dependency graph over the passes applicable to an execution request and
produces a deterministic :class:`ExecutionPlan`. Ordering is a Kahn topological
sort with a registration-order tiebreak, so identical inputs always yield an
identical plan — no timestamps, randomness, or machine-dependent ordering.

Validation performed before a plan is returned:

* metadata sanity (identifier/version present, requirements non-negative)
* dependency resolution (every declared dependency is a planned pass)
* cycle detection
* prerequisite satisfaction (against artifact capabilities plus capabilities
  provided by a pass's transitive dependencies)
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ExecutionRequest
from .errors import DependencyError, PlanningError, PrerequisiteError
from .passes import Pass
from .registry import PassRegistry

__all__ = ["ExecutionPlan", "Planner"]


@dataclass(frozen=True)
class ExecutionPlan:
    """An immutable, deterministic ordering of pass identifiers to execute."""

    ordered_ids: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.ordered_ids)


class Planner:
    """Deterministic execution planner over a pass registry."""

    def plan(self, registry: PassRegistry, request: ExecutionRequest) -> ExecutionPlan:
        passes = registry.all()
        reg_index = {p.metadata.identifier: i for i, p in enumerate(passes)}

        # 1. Applicability: keep passes applicable to at least one artifact.
        selected: list[Pass] = [
            p for p in passes if any(p.applies_to(a) for a in request.artifacts)
        ]
        selected_ids = {p.metadata.identifier for p in selected}
        by_id = {p.metadata.identifier: p for p in selected}

        # 2. Metadata validation.
        for p in selected:
            meta = p.metadata
            if not meta.identifier:
                raise PlanningError("pass has no identifier")
            if not meta.version:
                raise PlanningError("pass has no version", pass_id=meta.identifier)
            if not meta.requirements.is_valid():
                raise PlanningError("invalid execution requirements", pass_id=meta.identifier)

        # 3. Dependency resolution: every declared dependency must be planned.
        for p in selected:
            for dep in p.metadata.dependencies:
                if dep not in selected_ids:
                    if dep in reg_index:
                        raise DependencyError(
                            "dependency is not applicable to this request",
                            pass_id=p.metadata.identifier,
                            dependency=dep,
                        )
                    raise DependencyError(
                        "unknown dependency",
                        pass_id=p.metadata.identifier,
                        dependency=dep,
                    )

        # 4. Prerequisite satisfaction via transitive dependencies + artifacts.
        seed_caps = self._artifact_capabilities(request)
        for p in selected:
            available = seed_caps | self._transitive_provided_caps(p, by_id)
            missing = p.metadata.prerequisite_names() - available
            if missing:
                raise PrerequisiteError(
                    "unmet prerequisites",
                    pass_id=p.metadata.identifier,
                    missing=tuple(sorted(missing)),
                )

        # 5. Deterministic topological sort (Kahn, registration-order tiebreak).
        ordered = self._toposort(selected, by_id, reg_index)
        return ExecutionPlan(ordered_ids=tuple(ordered))

    @staticmethod
    def _artifact_capabilities(request: ExecutionRequest) -> frozenset[str]:
        caps: set[str] = set()
        for artifact in request.artifacts:
            caps.update(artifact.capabilities)
        return frozenset(caps)

    def _transitive_provided_caps(self, start: Pass, by_id: dict[str, Pass]) -> frozenset[str]:
        caps: set[str] = set()
        seen: set[str] = set()
        stack = list(start.metadata.dependencies)
        while stack:
            dep_id = stack.pop()
            if dep_id in seen or dep_id not in by_id:
                continue
            seen.add(dep_id)
            dep = by_id[dep_id]
            caps.update(dep.metadata.capability_names())
            stack.extend(dep.metadata.dependencies)
        return frozenset(caps)

    @staticmethod
    def _toposort(
        selected: list[Pass],
        by_id: dict[str, Pass],
        reg_index: dict[str, int],
    ) -> list[str]:
        indegree: dict[str, int] = {p.metadata.identifier: 0 for p in selected}
        successors: dict[str, list[str]] = {p.metadata.identifier: [] for p in selected}
        for p in selected:
            pid = p.metadata.identifier
            for dep in p.metadata.dependencies:
                successors[dep].append(pid)
                indegree[pid] += 1

        ordered: list[str] = []
        remaining = set(indegree)
        while remaining:
            ready = sorted(
                (pid for pid in remaining if indegree[pid] == 0),
                key=lambda pid: reg_index[pid],
            )
            if not ready:
                raise DependencyError(
                    "dependency cycle detected",
                    unresolved=tuple(sorted(remaining, key=lambda pid: reg_index[pid])),
                )
            for pid in ready:
                ordered.append(pid)
                remaining.discard(pid)
                for succ in successors[pid]:
                    indegree[succ] -= 1
        return ordered
