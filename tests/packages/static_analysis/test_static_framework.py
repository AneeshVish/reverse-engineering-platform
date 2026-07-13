"""Static-analysis tests: architecture-neutral framework interfaces."""

from __future__ import annotations

from reveng_static_analysis import (
    Architecture,
    CrossReference,
    FunctionBoundary,
    FunctionCandidate,
    FunctionMetadata,
    InstructionModel,
    ReferenceKind,
    ReferenceTarget,
)


def test_all_target_architectures_present() -> None:
    values = {a.value for a in Architecture}
    assert {"x86", "x64", "arm", "arm64", "mips", "powerpc", "riscv"} <= values


def test_instruction_model_is_neutral_placeholder() -> None:
    model = InstructionModel(architecture=Architecture.ARM64, address=0x1000)
    assert model.architecture is Architecture.ARM64
    assert model.instruction is None  # no decoder produces one


def test_cross_reference_framework() -> None:
    xref = CrossReference(
        kind=ReferenceKind.CALL,
        source_address=0x10,
        target=ReferenceTarget(name="func", address=0x20),
    )
    assert xref.kind is ReferenceKind.CALL
    assert xref.target.name == "func"


def test_function_candidate_framework() -> None:
    candidate = FunctionCandidate(
        boundary=FunctionBoundary(start=0x100, end=0x200),
        metadata=FunctionMetadata(name="main"),
    )
    assert candidate.boundary.start == 0x100
    assert candidate.metadata.name == "main"
