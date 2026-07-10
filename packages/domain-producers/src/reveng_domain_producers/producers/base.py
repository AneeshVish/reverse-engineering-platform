"""Reference-producer scaffolding.

``BaseProducer`` implements the full ``Producer`` contract in a pure,
deterministic way that concrete reference producers customize through a small set
of class attributes and hooks. It performs no deep reverse engineering — only
magic/extension matching, format validation, and normalized metadata.
"""

from __future__ import annotations

from reveng_core_substrate import HealthResult, HealthState

from ..artifact import build_artifact
from ..contracts import (
    CapabilityDescriptor,
    ClaimStrength,
    Producer,
    ProducerCapabilities,
    ProducerRequest,
    ProducerResult,
)

__all__ = ["BaseProducer"]


class BaseProducer(Producer):
    """Common, deterministic implementation for reference producers.

    Subclasses set ``name``, ``version``, ``artifact_type``, ``priority``,
    ``magic_prefixes``, ``extensions``, and ``capability_names``. Behavior is a
    pure function of the request; no global state or nondeterminism is introduced.
    """

    #: Byte prefixes that constitute a STRONG claim.
    magic_prefixes: tuple[bytes, ...] = ()
    #: Extensions (without dot) that constitute a WEAK claim when no magic matches.
    extensions: tuple[str, ...] = ()
    #: Capabilities advertised for produced artifacts.
    capability_names: tuple[str, ...] = ()
    #: Minimum content length required to validate.
    min_size: int = 1

    def identify(self, request: ProducerRequest) -> ClaimStrength:
        if self.magic_prefixes and any(
            request.content.startswith(p) for p in self.magic_prefixes
        ):
            return ClaimStrength.STRONG
        if self._extension_matches(request):
            return ClaimStrength.WEAK
        return ClaimStrength.NONE

    def validate(self, request: ProducerRequest) -> bool:
        if len(request.content) < self.min_size:
            return False
        if self.magic_prefixes:
            return any(request.content.startswith(p) for p in self.magic_prefixes) or (
                self._extension_matches(request)
            )
        return True

    def produce(self, request: ProducerRequest) -> ProducerResult:
        artifact = build_artifact(
            content=request.content,
            source_ref=request.source_ref,
            artifact_type=self.artifact_type,
            producer_name=self.name,
            producer_version=self.version,
            metadata=self._metadata(request),
            capabilities=self.capability_names,
        )
        return ProducerResult(artifact=artifact)

    def supported_capabilities(self) -> ProducerCapabilities:
        return ProducerCapabilities(
            descriptors=tuple(CapabilityDescriptor(name=n) for n in self.capability_names)
        )

    def health(self) -> HealthResult:
        return HealthResult(HealthState.HEALTHY)

    # -- hooks ---------------------------------------------------------------

    def _extension_matches(self, request: ProducerRequest) -> bool:
        ext = (request.hint_extension or "").lstrip(".").lower()
        return ext in self.extensions

    def _metadata(self, request: ProducerRequest) -> dict[str, object]:
        """Deterministic normalized metadata. Subclasses may extend."""

        return {
            "declared_type": self.artifact_type.value,
            "byte_length": len(request.content),
        }
