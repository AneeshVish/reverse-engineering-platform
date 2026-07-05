"""L2 — GCC/Clang compilation validation."""

import os
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class CompileResult:
    ok: bool
    stderr: str = ""


class CompilerAgent:
    """Compile candidate C and return diagnostics."""

    def __init__(self, compiler="gcc"):
        self.compiler = compiler

    def compile_and_check(self, source_code: str, extra_flags=None) -> CompileResult:
        flags = list(extra_flags or [])
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "candidate.c")
            obj = os.path.join(td, "candidate.o")
            with open(src, "w", encoding="utf-8") as f:
                f.write(source_code)
            cmd = [self.compiler, "-c", src, "-o", obj] + flags
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            except FileNotFoundError:
                return CompileResult(ok=False, stderr=f"{self.compiler} not found on PATH")
            except subprocess.TimeoutExpired:
                return CompileResult(ok=False, stderr="Compilation timed out")
            if res.returncode != 0:
                return CompileResult(ok=False, stderr=res.stderr or res.stdout)
            return CompileResult(ok=True)
