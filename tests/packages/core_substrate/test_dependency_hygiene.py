"""Substrate invariant: the substrate is the lowest runtime layer.

Enforces, by AST scan of the package source, that core-substrate imports only
the standard library and its four permitted libs — and never a sibling platform
package or an app. This is stricter than the shared ``check_dep_001`` validator
(which permits any lib), and it is the mechanical guard for the architecture
invariant "future packages depend on the substrate; the substrate never depends
on them".
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from reveng_testing import repo_root_from_tests

ALLOWED_LIBS = {
    "reveng_types",
    "reveng_errors",
    "reveng_logging",
    "reveng_config",
}

SELF = "reveng_core_substrate"


def _substrate_sources() -> list[Path]:
    root = repo_root_from_tests()
    src = root / "packages" / "core-substrate" / "src" / SELF
    files = [p for p in src.rglob("*.py") if "__pycache__" not in p.parts]
    assert files, f"no substrate sources found under {src}"
    return files


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # level > 0 is a relative (intra-package) import.
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def test_substrate_imports_only_stdlib_and_allowed_libs() -> None:
    stdlib = sys.stdlib_module_names
    violations: list[str] = []

    for path in _substrate_sources():
        for module in sorted(_top_level_imports(path)):
            if module in stdlib or module in ALLOWED_LIBS or module == SELF:
                continue
            violations.append(f"{path.name}: {module}")

    assert not violations, f"disallowed imports in core-substrate: {violations}"


def test_substrate_never_imports_a_sibling_package_or_app() -> None:
    root = repo_root_from_tests()
    siblings = {
        f"reveng_{p.name.replace('-', '_')}"
        for p in (root / "packages").iterdir()
        if p.is_dir() and p.name != "core-substrate"
    }
    apps = {"reveng_api", "reveng_worker", "reveng_desktop"}
    forbidden = siblings | apps

    violations: list[str] = []
    for path in _substrate_sources():
        for module in _top_level_imports(path) & forbidden:
            violations.append(f"{path.name}: {module}")

    assert not violations, f"substrate depends upward: {violations}"
