"""The analyzer abstraction.

An ``Analyzer`` declares itself via ``AnalyzerMetadata`` and implements
``analyze``. Analyzers are pure and deterministic: identical context ⇒ identical
extraction, with no global state, timestamps, randomness, or machine-specific
behavior.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from reveng_domain_producers import Artifact, ArtifactType

from .contracts import AnalysisCapability, AnalysisContext, AnalysisResult

__all__ = [
    "AnalyzerCapability",
    "AnalyzerPriority",
    "AnalyzerState",
    "AnalyzerMetadata",
    "Analyzer",
    "DEFAULT_PRIORITY",
]

# Reference analyzers register at this priority; third parties override by
# declaring a higher value.
DEFAULT_PRIORITY = 100

# ``AnalyzerCapability`` is the same vocabulary as ``AnalysisCapability``.
AnalyzerCapability = AnalysisCapability

# Selection priority is a plain integer.
AnalyzerPriority = int


class AnalyzerState(str, Enum):
    """Lifecycle state of an analyzer within an analysis run."""

    REGISTERED = "registered"
    SELECTED = "selected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class AnalyzerMetadata:
    """An analyzer's self-description, validated by the planner before use."""

    identifier: str
    version: str = "0.0.0"
    capabilities: tuple[AnalyzerCapability, ...] = ()
    applicable_types: tuple[ArtifactType, ...] = ()
    priority: int = DEFAULT_PRIORITY

    def applies_to_type(self, artifact_type: ArtifactType) -> bool:
        if not self.applicable_types:
            return True
        return artifact_type in self.applicable_types

    def capability_names(self) -> frozenset[str]:
        return frozenset(c.value for c in self.capabilities)


class Analyzer(ABC):
    """Abstract static analyzer."""

    @property
    @abstractmethod
    def metadata(self) -> AnalyzerMetadata:
        """Return this analyzer's self-description."""

    @property
    def identifier(self) -> str:
        return self.metadata.identifier

    def applies_to(self, artifact: Artifact) -> bool:
        """Whether this analyzer applies to ``artifact`` (default: by type)."""

        return self.metadata.applies_to_type(artifact.artifact_type)

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        """Run the analyzer and return its extraction result."""
