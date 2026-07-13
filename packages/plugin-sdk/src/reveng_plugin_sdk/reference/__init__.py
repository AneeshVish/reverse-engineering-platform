"""Built-in reference plugins.

Three minimal, deterministic plugins that demonstrate extension registration only.
They declare capabilities against real backend extension points (producer,
analysis, reporting) to show that plugins may integrate with every subsystem, but
they implement no reverse-engineering functionality and never invoke managers. A
small dependency chain (producer -> analysis -> reporting) exercises deterministic
load ordering.
"""

from __future__ import annotations

from reveng_domain_producers import ArtifactType
from reveng_reasoning import InferenceKind
from reveng_reporting import SectionKind

from ..capabilities import CapabilityDescriptor, CapabilityKind, ExtensionPoint
from ..metadata import PluginMetadata
from ..plugin import Plugin

__all__ = [
    "ExampleProducerPlugin",
    "ExampleAnalysisPlugin",
    "ExampleReportingPlugin",
    "REFERENCE_PLUGIN_TYPES",
    "reference_plugins",
]


class ExampleProducerPlugin(Plugin):
    """Demonstrates a producer-registry extension (integrates with domain-producers)."""

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            identifier="example_producer",
            name="Example Producer Plugin",
            version="1.0.0",
            author="reveng",
            description="Registers an example producer capability.",
            capabilities=(
                CapabilityDescriptor(
                    kind=CapabilityKind.PRODUCER,
                    extension_point=ExtensionPoint.PRODUCER_REGISTRY,
                    name="example_producer_capability",
                    description=f"example producer for artifact type {ArtifactType.RAW_BINARY.value}",
                ),
            ),
        )


class ExampleAnalysisPlugin(Plugin):
    """Demonstrates an analysis extension (integrates with reasoning)."""

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            identifier="example_analysis",
            name="Example Analysis Plugin",
            version="1.0.0",
            author="reveng",
            description="Registers an example analysis capability.",
            capabilities=(
                CapabilityDescriptor(
                    kind=CapabilityKind.ANALYSIS,
                    extension_point=ExtensionPoint.ANALYZER_REGISTRY,
                    name="example_analysis_capability",
                    description=f"example analysis producing {InferenceKind.STRUCTURAL.value} inferences",
                ),
            ),
            dependencies=("example_producer",),
        )


class ExampleReportingPlugin(Plugin):
    """Demonstrates a reporting-template extension (integrates with reporting)."""

    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            identifier="example_reporting",
            name="Example Reporting Plugin",
            version="1.0.0",
            author="reveng",
            description="Registers an example reporting capability.",
            capabilities=(
                CapabilityDescriptor(
                    kind=CapabilityKind.REPORTING,
                    extension_point=ExtensionPoint.REPORTING_TEMPLATE,
                    name="example_reporting_capability",
                    description=f"example report section of kind {SectionKind.APPENDIX.value}",
                ),
            ),
            dependencies=("example_analysis",),
        )


REFERENCE_PLUGIN_TYPES: tuple[type[Plugin], ...] = (
    ExampleProducerPlugin,
    ExampleAnalysisPlugin,
    ExampleReportingPlugin,
)


def reference_plugins() -> tuple[Plugin, ...]:
    """Return fresh instances of the reference plugins."""

    return tuple(cls() for cls in REFERENCE_PLUGIN_TYPES)
