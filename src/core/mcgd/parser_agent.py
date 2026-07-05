"""L1 — Tree-sitter syntax validation."""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class SyntaxResult:
    ok: bool
    error_lines: List[int] = field(default_factory=list)
    message: str = ""


class ParserAgent:
    """Validate C syntax; extract error line ranges for targeted repair."""

    def __init__(self):
        self._parser = None
        self._language = None
        self._init_tree_sitter()

    def _init_tree_sitter(self):
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_c
            self._language = Language(tree_sitter_c.language())
            self._parser = Parser(self._language)
        except Exception:
            self._parser = None

    @property
    def available(self) -> bool:
        return self._parser is not None

    def check_syntax(self, code_str: str) -> SyntaxResult:
        if not self._parser:
            return self._fallback_check(code_str)
        tree = self._parser.parse(bytes(code_str, "utf8"))
        if not tree.root_node.has_error:
            return SyntaxResult(ok=True)
        lines = self._error_lines(tree.root_node, code_str)
        return SyntaxResult(
            ok=False,
            error_lines=lines,
            message=f"Syntax errors on lines: {lines}",
        )

    def _error_lines(self, node, code_str: str) -> List[int]:
        lines = set()
        if node.type == "ERROR" or node.is_missing:
            lines.add(node.start_point[0] + 1)
        for i in range(node.child_count):
            lines.update(self._error_lines(node.child(i), code_str))
        return sorted(lines)

    def _fallback_check(self, code_str: str) -> SyntaxResult:
        """Brace/paren balance heuristic when tree-sitter unavailable."""
        if code_str.count("{") != code_str.count("}"):
            return SyntaxResult(ok=False, message="Unbalanced braces", error_lines=[1])
        if code_str.count("(") != code_str.count(")"):
            return SyntaxResult(ok=False, message="Unbalanced parens", error_lines=[1])
        return SyntaxResult(ok=True)

    def repair_prompt_context(self, code_str: str, error_lines: List[int]) -> str:
        if not error_lines:
            return code_str
        lines = code_str.splitlines()
        chunks = []
        for ln in error_lines[:5]:
            start = max(0, ln - 2)
            end = min(len(lines), ln + 1)
            snippet = "\n".join(f"{start + i + 1}: {lines[start + i]}" for i in range(end - start))
            chunks.append(snippet)
        return "\n\n".join(chunks)
