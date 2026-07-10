"""Producer manager — thin ingestion orchestration.

The manager does exactly six things: discover, identify, select, invoke,
normalize, and return an :class:`Artifact`. It holds no mutable state of its own,
performs no caching, scheduling, queueing, storage, retrying, or threading — those
belong to later packages. It participates in the substrate lifecycle via the
``Component`` shape so a host ``Application`` can bring it up and register the
reference producers.
"""

from __future__ import annotations

from reveng_core_substrate import HealthAggregator, HealthResult, HealthState

from .artifact import Artifact, ArtifactType
from .contracts import ProducerRequest
from .errors import ValidationError
from .identification import identify_type
from .registry import ProducerRegistry
from .selection import select_producer

__all__ = ["ProducerManager"]


class ProducerManager:
    """Lifecycle-aware, stateless orchestrator over a producer registry."""

    component_name = "domain-producers.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        registry: ProducerRegistry,
        *,
        auto_register_builtins: bool = True,
    ) -> None:
        self._registry = registry
        self._auto_register_builtins = auto_register_builtins

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        """Register the reference producers unless the registry is preloaded."""

        if self._auto_register_builtins and len(self._registry) == 0:
            # Imported lazily to keep the module import graph acyclic.
            from .producers import register_builtin_producers

            register_builtin_producers(self._registry)

    def shutdown(self) -> None:
        """No resources are held; shutdown is a clean no-op."""

    # -- ingestion pipeline --------------------------------------------------

    def discover(self) -> tuple[str, ...]:
        """List available producer names (registration order)."""

        return self._registry.names()

    def identify(self, request: ProducerRequest) -> ArtifactType:
        """Return the hinted artifact type for a request (advisory only)."""

        return identify_type(request.content, request.hint_extension)

    def produce(self, request: ProducerRequest) -> Artifact:
        """Run the full pipeline and return a normalized artifact.

        discover → identify (advisory) → select → validate → invoke → normalize.
        """

        producer = select_producer(self._registry, request)
        if not producer.validate(request):
            raise ValidationError(
                "content failed producer validation",
                producer=producer.name,
                source_ref=request.source_ref,
            )
        result = producer.produce(request)
        return result.artifact

    # -- health --------------------------------------------------------------

    def health(self) -> HealthResult:
        """Aggregate the health of all registered producers."""

        aggregator = HealthAggregator()
        for producer in self._registry.all():
            aggregator.register(producer.name, producer.health)
        overall = aggregator.evaluate().overall
        return HealthResult(overall, detail=f"{len(self._registry)} producers")

    def health_state(self) -> HealthState:
        return self.health().state
