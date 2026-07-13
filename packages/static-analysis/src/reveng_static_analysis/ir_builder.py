"""Canonical IR generation from extraction results.

Converts an artifact plus its aggregated ``ExtractionResult`` into a canonical
``IRModule`` using the builders from ``reveng_intermediate_representation``. The
module name derives from the artifact content hash, and entities are added in
sorted order, so identical inputs always yield an identical module.

Only entities the IR builder can express are added as nodes: sections, symbols,
and imports/exports (as symbols). Other extracted entities (strings, resources,
relocations, segments, headers) are emitted as evidence elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reveng_domain_producers import Artifact
from reveng_intermediate_representation import (
    IRBuilder,
    IRIdentifier,
    IRModule,
    Symbol,
    SymbolKind,
)

from .extraction import ExtractionResult

__all__ = ["IRBuildResult", "IRArtifactBuilder"]


@dataclass(frozen=True)
class IRBuildResult:
    """The built module plus a map from entity key to the created IR node id."""

    module: IRModule
    node_ids: dict[str, IRIdentifier] = field(default_factory=dict)


def _unique_sorted(names: tuple[str, ...]) -> list[str]:
    return sorted({n for n in names if n})


class IRArtifactBuilder:
    """Builds a canonical ``IRModule`` from an artifact and its extraction."""

    def __init__(self) -> None:
        self._builder = IRBuilder()

    def build(self, artifact: Artifact, extraction: ExtractionResult) -> IRBuildResult:
        module_name = f"artifact:{artifact.identity.content_hash}"
        mb = self._builder.module(
            module_name,
            architecture="unknown",
            file_format=artifact.artifact_type.value,
        )
        node_ids: dict[str, IRIdentifier] = {}

        for name in _unique_sorted(tuple(s.name for s in extraction.sections)):
            size = next((s.size for s in extraction.sections if s.name == name), 0)
            node_ids[f"section:{name}"] = mb.add_section(name, size=size)

        for name in _unique_sorted(tuple(s.name for s in extraction.symbols)):
            node_ids[f"symbol:{name}"] = mb.add_symbol(
                Symbol(name=name, kind=SymbolKind.UNKNOWN)
            )

        for name in _unique_sorted(tuple(i.name for i in extraction.imports)):
            node_ids[f"import:{name}"] = mb.add_symbol(
                Symbol(name=name, kind=SymbolKind.IMPORT)
            )

        for name in _unique_sorted(tuple(e.name for e in extraction.exports)):
            node_ids[f"export:{name}"] = mb.add_symbol(
                Symbol(name=name, kind=SymbolKind.EXPORT)
            )

        return IRBuildResult(module=mb.build(), node_ids=node_ids)
