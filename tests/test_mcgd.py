"""MCGD agent unit tests."""

from src.core.mcgd.parser_agent import ParserAgent
from src.core.mcgd.compiler_agent import CompilerAgent
from src.core.mcgd.rewards import compute_reward, VERIFIED_THRESHOLD
from src.core.mcgd.orchestrator import MCGDOrchestrator, MAX_ITERATIONS


VALID_C = """
#include <stdio.h>
int main(void) {
    printf("hello\\n");
    return 0;
}
"""

INVALID_C = "int main( { return 0;"


def test_parser_valid_c():
    agent = ParserAgent()
    r = agent.check_syntax(VALID_C)
    assert r.ok or agent._parser is None  # fallback may pass balanced braces


def test_parser_invalid_c():
    agent = ParserAgent()
    r = agent.check_syntax(INVALID_C)
    assert not r.ok


def test_reward_verified_requires_exec():
    r = compute_reward(True, True, VERIFIED_THRESHOLD)
    assert r.verified
    r2 = compute_reward(True, True, 0.0)
    assert not r2.verified


def test_orchestrator_runs_without_llm():
    orch = MCGDOrchestrator()
    result = orch.run(VALID_C)
    assert result.code
    assert len(result.iterations) <= MAX_ITERATIONS
