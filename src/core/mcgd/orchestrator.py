"""MCGD orchestrator — Ralph-style max 5 iteration loop."""

import logging
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from src.core.mcgd.parser_agent import ParserAgent
from src.core.mcgd.compiler_agent import CompilerAgent
from src.core.mcgd.execution_agent import ExecutionAgent
from src.core.mcgd.rewards import compute_reward, RewardScore
from src.core.mcgd import repair_prompt

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 5
SPAWN_BUDGET_DEFAULT_CONTEXT = 50000


@dataclass
class IterationLog:
    iteration: int
    l1_ok: bool
    l2_ok: bool
    l3_pass_rate: float
    reward: RewardScore
    message: str = ""


@dataclass
class MCGDResult:
    code: str
    verified: bool
    iterations: List[IterationLog] = field(default_factory=list)
    final_reward: float = 0.0


class MCGDOrchestrator:
    """L1 → L2 → L3 loop with Policy LLM repair callbacks."""

    def __init__(
        self,
        policy_llm: Optional[Callable[[str], str]] = None,
        original_binary: str = "",
    ):
        self.parser = ParserAgent()
        self.compiler = CompilerAgent()
        self.executor = ExecutionAgent()
        self.policy_llm = policy_llm
        self.original_binary = original_binary

    def run(self, raw_c: str) -> MCGDResult:
        code = raw_c
        logs: List[IterationLog] = []
        best_reward = 0.0
        verified = False

        for i in range(1, MAX_ITERATIONS + 1):
            syn = self.parser.check_syntax(code)
            if not syn.ok and self.policy_llm:
                ctx = self.parser.repair_prompt_context(code, syn.error_lines)
                prompt = repair_prompt.syntax_repair_prompt(code, ctx)
                code = self.policy_llm(prompt) or code
                syn = self.parser.check_syntax(code)

            comp = self.compiler.compile_and_check(code)
            if not comp.ok and self.policy_llm:
                prompt = repair_prompt.compile_repair_prompt(code, comp.stderr)
                code = self.policy_llm(prompt) or code
                comp = self.compiler.compile_and_check(code)

            exec_res = ExecutionAgent().run_differential(
                self.original_binary, code) if self.original_binary else None
            pass_rate = exec_res.pass_rate if exec_res else 0.0

            if exec_res and pass_rate < 1.0 and self.policy_llm and comp.ok:
                prompt = repair_prompt.exec_repair_prompt(
                    code, "\n".join(exec_res.details))
                code = self.policy_llm(prompt) or code
                exec_res = self.executor.run_differential(self.original_binary, code)
                pass_rate = exec_res.pass_rate

            reward = compute_reward(syn.ok, comp.ok, pass_rate)
            best_reward = max(best_reward, reward.total)
            verified = reward.verified
            msg = syn.message or comp.stderr or ""
            logs.append(IterationLog(i, syn.ok, comp.ok, pass_rate, reward, msg))
            if verified:
                break

        return MCGDResult(code=code, verified=verified, iterations=logs, final_reward=best_reward)
