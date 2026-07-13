"""Invariant: IR depends only downward and is decoupled from ingestion.

AST-scans the package source and asserts it imports only the standard library,
the four permitted engineering libs, and ``reveng_core_substrate`` — never
``reveng_domain_producers``, any other sibling package, or an app.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from reveng_testing import repo_root_from_tests

ALLOWED = {
    "reveng_types",
    "reveng_errors",
    "reveng_logging",
    "reveng_config",
    "reveng_core_substrate",
}

SELF = "reveng_intermediate_representation"


def _sources() -> list[Path]:
    root = repo_root_from_tests()
    src = root / "packages" / "intermediate-representation" / "src" / SELF
    files = [p for p in src.rglob("*.py") if "__pycache__" not in p.parts]
    assert files, f"no sources under {src}"
    return files


def _top_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def test_imports_only_allowed_modules() -> None:
    stdlib = sys.stdlib_module_names
    violations: list[str] = []
    for path in _sources():
        for module in sorted(_top_imports(path)):
            if module in stdlib or module in ALLOWED or module == SELF:
                continue
            violations.append(f"{path.name}: {module}")
    assert not violations, f"disallowed imports: {violations}"


def test_decoupled_from_domain_producers() -> None:
    for path in _sources():
        assert "reveng_domain_producers" not in _top_imports(path), (
            f"{path.name} imports domain-producers; IR must stay decoupled"
        )


def test_no_sibling_or_app_imports() -> None:
    root = repo_root_from_tests()
    siblings = {
        f"reveng_{p.name.replace('-', '_')}"
        for p in (root / "packages").iterdir()
        if p.is_dir() and p.name not in ("intermediate-representation", "core-substrate")
    }
    apps = {"reveng_api", "reveng_worker", "reveng_desktop"}
    forbidden = siblings | apps
    violations: list[str] = []
    for path in _sources():
        for module in _top_imports(path) & forbidden:
            violations.append(f"{path.name}: {module}")
    assert not violations, f"forbidden imports: {violations}"
