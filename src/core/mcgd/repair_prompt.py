"""Targeted LLM repair prompts per MCGD failure type."""

SYNTAX_REPAIR = """Fix ONLY the syntax errors in this C fragment. Return valid C only.
Errors were reported on these lines:
{context}

Full source:
{code}
"""

COMPILE_REPAIR = """Fix compilation errors in this C code. Compiler stderr:
{stderr}

Source:
{code}
"""

EXEC_REPAIR = """The decompiled C compiles but behaves differently from the original binary.
Execution mismatches:
{details}

Fix the logic. Source:
{code}
"""


def syntax_repair_prompt(code: str, context: str) -> str:
    return SYNTAX_REPAIR.format(context=context, code=code)


def compile_repair_prompt(code: str, stderr: str) -> str:
    return COMPILE_REPAIR.format(stderr=stderr, code=code)


def exec_repair_prompt(code: str, details: str) -> str:
    return EXEC_REPAIR.format(details=details, code=code)
