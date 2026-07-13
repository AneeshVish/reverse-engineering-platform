"""Shared builders for knowledge-graph tests."""

from __future__ import annotations

from reveng_intermediate_representation import IRBuilder, IRModule, Symbol, SymbolKind
from reveng_storage_evidence import (
    Evidence,
    EvidenceConfidence,
    EvidenceKind,
    build_evidence,
)

ARTIFACT_REF = "artHASH0000"


def build_sample_ir(name: str = "libfoo") -> IRModule:
    mb = IRBuilder().module(name, architecture="x86_64", file_format="elf")
    mb.add_section(".text", size=100)
    mb.add_symbol(Symbol(name="main", kind=SymbolKind.UNKNOWN))
    mb.add_symbol(Symbol(name="printf", kind=SymbolKind.IMPORT))
    mb.add_symbol(Symbol(name="run", kind=SymbolKind.EXPORT))
    return mb.build()


def build_sample_evidence(ir: IRModule) -> tuple[Evidence, ...]:
    return (
        build_evidence(
            key="e1",
            kind=EvidenceKind.IR_MODULE,
            confidence=EvidenceConfidence.EXTRACTED,
            ir_refs=(ir.root,),
            artifact_ref=ARTIFACT_REF,
        ),
        build_evidence(
            key="e2",
            kind=EvidenceKind.ARTIFACT,
            confidence=EvidenceConfidence.OBSERVED,
            artifact_ref=ARTIFACT_REF,
        ),
    )


def build_sample() -> tuple[IRModule, tuple[Evidence, ...]]:
    ir = build_sample_ir()
    return ir, build_sample_evidence(ir)
