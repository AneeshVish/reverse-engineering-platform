"""Shared builders for IR tests."""

from __future__ import annotations

from reveng_intermediate_representation import (
    FunctionSignature,
    ImmediateOperand,
    Instruction,
    IRModule,
    ModuleBuilder,
    RegisterOperand,
)


def build_sample_module(name: str = "libfoo") -> IRModule:
    """Build a small but representative module deterministically."""

    mb = ModuleBuilder(name, architecture="x86_64", file_format="elf")
    mb.add_section(".text", size=100)
    fb = mb.function_builder("main", FunctionSignature(name="main"))
    block = fb.add_basic_block("entry")
    ib = fb.instruction_builder(block, "entry")
    ib.build(
        0,
        Instruction(
            mnemonic="mov",
            operands=(RegisterOperand(register="rax"), ImmediateOperand(value=1)),
        ),
    )
    return mb.build()
