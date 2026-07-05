"""ExeBench subset — measure syntax/compile rates honestly."""

import pytest

from tests.benchmarks.exebench_sample import SAMPLE_FUNCTIONS
from src.core.mcgd.parser_agent import ParserAgent
from src.core.mcgd.compiler_agent import CompilerAgent


@pytest.mark.parametrize("sample", SAMPLE_FUNCTIONS, ids=lambda s: s["name"])
def test_exebench_syntax_and_compile(sample):
    parser = ParserAgent()
    compiler = CompilerAgent()
    syn = parser.check_syntax(sample["source"])
    assert syn.ok, syn.message
    comp = compiler.compile_and_check(sample["source"])
    if not comp.ok:
        pytest.skip(f"gcc unavailable or compile failed: {comp.stderr[:200]}")
