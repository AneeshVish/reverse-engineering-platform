"""Plugin capability model.

Capabilities are the immutable, declarative way a plugin states which platform
extension point it contributes to. They carry no execution logic — a manager reads
a capability to know where a plugin may hook, and invokes the plugin itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["CapabilityKind", "ExtensionPoint", "CapabilityDescriptor"]


class CapabilityKind(str, Enum):
    """The semantic category of a plugin capability."""

    PRODUCER = "producer"
    PASS = "pass"
    ANALYSIS = "analysis"
    GRAPH = "graph"
    REASONING = "reasoning"
    INVESTIGATION = "investigation"
    REPORTING = "reporting"
    GENERIC = "generic"


class ExtensionPoint(str, Enum):
    """A named platform extension point a capability may hook into.

    These correspond to the registries/managers the backend already exposes;
    plugins register through them and are invoked by the owning manager.
    """

    PRODUCER_REGISTRY = "producer_registry"
    PASS_REGISTRY = "pass_registry"
    ANALYZER_REGISTRY = "analyzer_registry"
    GRAPH_BUILDER = "graph_builder"
    REASONING_RULES = "reasoning_rules"
    INVESTIGATION_BUILDER = "investigation_builder"
    REPORTING_TEMPLATE = "reporting_template"
    GENERIC = "generic"


@dataclass(frozen=True)
class CapabilityDescriptor:
    """An immutable declaration of one capability a plugin contributes."""

    kind: CapabilityKind
    extension_point: ExtensionPoint
    name: str
    description: str = ""
