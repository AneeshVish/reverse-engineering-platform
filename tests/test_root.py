"""Sanity test: core package imports without optional heavy deps."""


def test_core_imports():
    import src  # noqa: F401
    from src.core import capabilities  # noqa: F401
    from src.core.disassembler import DisassemblerEngine  # noqa: F401
    from src.core.universal_loader import UniversalLoader  # noqa: F401
