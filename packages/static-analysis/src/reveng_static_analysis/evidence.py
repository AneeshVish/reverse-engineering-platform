"""Canonical evidence emission from extraction results.

Converts an artifact, its extraction, and the built IR into deterministic
``Evidence`` records using ``reveng_storage_evidence.build_evidence``. Keys derive
from the artifact content hash and the entity identity, so identical inputs always
produce identical evidence ids. Records may optionally be emitted into a
``StorageManager`` (the in-memory store; no persistence backend).
"""

from __future__ import annotations

from reveng_domain_producers import Artifact
from reveng_intermediate_representation import IRIdentifier
from reveng_storage_evidence import (
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    EvidenceOrigin,
    StorageManager,
    build_evidence,
)

from .extraction import ExtractionResult
from .ir_builder import IRBuildResult

__all__ = ["EvidenceBuilder"]

_ORIGIN = EvidenceOrigin(origin_kind="static-analysis", reference="static-analysis")


class EvidenceBuilder:
    """Builds deterministic evidence records from extraction and IR."""

    def build(
        self,
        artifact: Artifact,
        extraction: ExtractionResult,
        ir_result: IRBuildResult,
    ) -> tuple[Evidence, ...]:
        prefix = artifact.identity.content_hash
        records: list[Evidence] = []

        # Artifact-level anchor (an observed fact about the input).
        records.append(
            build_evidence(
                key=f"{prefix}:artifact",
                kind=EvidenceKind.ARTIFACT,
                confidence=EvidenceConfidence.OBSERVED,
                origin=_ORIGIN,
                payload={
                    "content_hash": prefix,
                    "type": artifact.artifact_type.value,
                    "size": artifact.source.size,
                },
                artifact_ref=prefix,
            )
        )

        # The produced IR module.
        records.append(
            build_evidence(
                key=f"{prefix}:module",
                kind=EvidenceKind.IR_MODULE,
                confidence=EvidenceConfidence.EXTRACTED,
                origin=_ORIGIN,
                payload={"root": ir_result.module.root.value},
                ir_refs=(ir_result.module.root,),
                artifact_ref=prefix,
            )
        )

        # Entities that became IR nodes.
        for entity_key, node_id in ir_result.node_ids.items():
            category, _, name = entity_key.partition(":")
            records.append(
                self._node_evidence(prefix, category, name, node_id)
            )

        # Extracted entities with no IR node (properties only).
        for s in extraction.strings:
            records.append(
                build_evidence(
                    key=f"{prefix}:string:{s.offset}:{s.value}",
                    kind=EvidenceKind.PROPERTY,
                    confidence=EvidenceConfidence.EXTRACTED,
                    origin=_ORIGIN,
                    payload={"value": s.value, "offset": s.offset, "encoding": s.encoding},
                    artifact_ref=prefix,
                )
            )
        for h in extraction.headers:
            records.append(
                build_evidence(
                    key=f"{prefix}:header:{h.name}",
                    kind=EvidenceKind.PROPERTY,
                    confidence=EvidenceConfidence.EXTRACTED,
                    origin=_ORIGIN,
                    payload={"name": h.name, "value": h.value},
                    artifact_ref=prefix,
                )
            )

        # Deduplicate by content-derived id, then order deterministically.
        unique = {e.id.value: e for e in records}
        return tuple(sorted(unique.values(), key=lambda e: e.id.value))

    @staticmethod
    def _node_evidence(
        prefix: str, category: str, name: str, node_id: IRIdentifier
    ) -> Evidence:
        return build_evidence(
            key=f"{prefix}:{category}:{name}",
            kind=EvidenceKind.IR_NODE,
            confidence=EvidenceConfidence.EXTRACTED,
            origin=_ORIGIN,
            payload={"category": category, "name": name},
            ir_refs=(node_id,),
            artifact_ref=prefix,
        )

    def store(self, manager: StorageManager, evidences: tuple[Evidence, ...]) -> None:
        """Emit evidence into an in-memory storage manager (idempotent-safe skip)."""

        for evidence in evidences:
            if not manager.repository.contains(evidence.id):
                manager.add(evidence)
