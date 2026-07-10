"""Pass-engine value contracts.

Declarative types a pass uses to describe itself and the inputs a run operates
over. These are pure data; behavior lives in the pass, planner, and scheduler.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reveng_domain_producers import Artifact, ArtifactType

__all__ = [
    "Capability",
    "Prerequisite",
    "Applicability",
    "ExecutionRequirements",
    "ExecutionRequest",
]


@dataclass(frozen=True)
class Capability:
    """A named capability a pass makes available to downstream passes."""

    name: str


@dataclass(frozen=True)
class Prerequisite:
    """A named capability a pass requires before it can run."""

    name: str


@dataclass(frozen=True)
class Applicability:
    """Which artifacts a pass applies to.

    An empty ``artifact_types`` means the pass applies to every artifact.
    """

    artifact_types: tuple[ArtifactType, ...] = ()

    def matches(self, artifact: Artifact) -> bool:
        if not self.artifact_types:
            return True
        return artifact.artifact_type in self.artifact_types


@dataclass(frozen=True)
class ExecutionRequirements:
    """Declarative resource hints, validated (non-negative) before execution.

    Purely declarative in this phase — no accounting or enforcement happens here
    (that belongs to later phases).
    """

    memory_mb: int = 0
    cpu_cores: int = 0

    def is_valid(self) -> bool:
        return self.memory_mb >= 0 and self.cpu_cores >= 0


@dataclass(frozen=True)
class ExecutionRequest:
    """The inputs of an execution run: the artifacts passes operate over."""

    artifacts: tuple[Artifact, ...] = field(default_factory=tuple)
