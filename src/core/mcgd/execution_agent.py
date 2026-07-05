"""L3 — Differential execution sandbox (function-scoped MVP)."""

import os
import random
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExecutionResult:
    pass_rate: float
    total: int
    passed: int
    details: List[str] = field(default_factory=list)


class ExecutionAgent:
    """Run original binary vs compiled candidate with identical inputs."""

    def __init__(self, num_cases: int = 5, timeout: float = 5.0):
        self.num_cases = num_cases
        self.timeout = timeout

    def run_differential(
        self,
        original_binary: str,
        candidate_source: str,
        compiler="gcc",
    ) -> ExecutionResult:
        if not original_binary or not os.path.isfile(original_binary):
            return ExecutionResult(0.0, 0, 0, ["Original binary not available"])
        with tempfile.TemporaryDirectory() as td:
            cand_src = os.path.join(td, "candidate.c")
            cand_bin = os.path.join(td, "candidate")
            with open(cand_src, "w", encoding="utf-8") as f:
                f.write(candidate_source)
            compile_cmd = [compiler, cand_src, "-o", cand_bin]
            try:
                cr = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
            except FileNotFoundError:
                return ExecutionResult(0.0, 0, 0, [f"{compiler} not found"])
            if cr.returncode != 0:
                return ExecutionResult(0.0, 0, 0, [cr.stderr or "Candidate compile failed"])

            passed = 0
            details = []
            for i in range(self.num_cases):
                seed = random.randint(0, 2**31 - 1)
                env = os.environ.copy()
                env["MCGD_SEED"] = str(seed)
                orig = self._run_binary(original_binary, env)
                cand = self._run_binary(cand_bin, env)
                ok = orig["exit"] == cand["exit"] and orig["stdout"] == cand["stdout"]
                if ok:
                    passed += 1
                else:
                    details.append(
                        f"case {i}: orig exit={orig['exit']} cand exit={cand['exit']}")
            total = self.num_cases
            return ExecutionResult(passed / total if total else 0.0, total, passed, details)

    def _run_binary(self, path: str, env: dict) -> dict:
        try:
            r = subprocess.run(
                [path], capture_output=True, text=True, timeout=self.timeout, env=env,
            )
            return {"exit": r.returncode, "stdout": r.stdout}
        except subprocess.TimeoutExpired:
            return {"exit": -1, "stdout": ""}
        except Exception as e:
            return {"exit": -2, "stdout": str(e)}
