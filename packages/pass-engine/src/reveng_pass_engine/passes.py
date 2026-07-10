"""The pass abstraction.

A ``Pass`` is a unit of coordinated work. It declares itself via ``PassMetadata``
(identifier, version, capabilities, prerequisites, dependencies, applicability,
execution requirements) and implements ``run``. The engine coordinates passes; it
never interprets what a pass produces.

Passes must be pure and deterministic: identical context ⇒ identical result, with
no global state, timestamps, randomness, or machine-specific behavior.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from reveng_domain_producers import Artifact

from .contracts import (
    Applicability,
    Capability,
    ExecutionRequirements,
    Prerequisite,
)
from .context import PassContext
from .results import PassResult

__all__ = ["PassState", "PassMetadata", "Pass"]


class PassState(str, Enum):
    """Lifecycle state of a pass within an execution run."""

    REGISTERED = "registered"
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class PassMetadata:
    """A pass's self-description, validated by the planner before execution."""

    identifier: str
    version: str = "0.0.0"
    capabilities: tuple[Capability, ...] = ()
    prerequisites: tuple[Prerequisite, ...] = ()
    dependencies: tuple[str, ...] = ()
    applicability: Applicability = field(default_factory=Applicability)
    requirements: ExecutionRequirements = field(default_factory=ExecutionRequirements)

    def capability_names(self) -> frozenset[str]:
        return frozenset(c.name for c in self.capabilities)

    def prerequisite_names(self) -> frozenset[str]:
        return frozenset(p.name for p in self.prerequisites)


class Pass(ABC):
    """Abstract coordinated work unit."""

    @property
    @abstractmethod
    def metadata(self) -> PassMetadata:
        """Return this pass's self-description."""

    @property
    def identifier(self) -> str:
        return self.metadata.identifier

    def applies_to(self, artifact: Artifact) -> bool:
        """Whether this pass applies to ``artifact`` (default: by applicability)."""

        return self.metadata.applicability.matches(artifact)

    @abstractmethod
    def run(self, context: PassContext) -> PassResult:
        """Execute the pass and return a result with an opaque payload."""
