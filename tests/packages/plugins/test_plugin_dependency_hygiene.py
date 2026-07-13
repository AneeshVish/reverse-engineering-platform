"""Invariant: the plugin SDK depends only downward.

AST-scans the package source and asserts it imports only the standard library,
the four engineering libs, the substrate, and the nine other backend subsystems.
The plugin SDK is uniquely permitted to import every backend, but it must not
import apps or the upper-tier reserved siblings (public-api, deployment,
observability, security, platform-validation).
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
    "reveng_domain_producers",
    "reveng_pass_engine",
    "reveng_intermediate_representation",
    "reveng_storage_evidence",
    "reveng_static_analysis",
    "reveng_knowledge_graph",
    "reveng_reasoning",
    "reveng_investigation",
    "reveng_reporting",
}

SELF = "reveng_plugin_sdk"

# The nine backend packages the SDK is allowed to integrate with (their dir names).
BACKEND_PKGS = {
    "core-substrate",
    "domain-producers",
    "pass-engine",
    "intermediate-representation",
    "storage-evidence",
    "static-analysis",
    "knowledge-graph",
    "reasoning",
    "investigation",
    "reporting",
    "plugin-sdk",
}


def _sources() -> list[Path]:
    root = repo_root_from_tests()
    src = root / "packages" / "plugin-sdk" / "src" / SELF
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


def test_no_forbidden_sibling_or_app_imports() -> None:
    root = repo_root_from_tests()
    siblings = {
        f"reveng_{p.name.replace('-', '_')}"
        for p in (root / "packages").iterdir()
        if p.is_dir() and p.name not in BACKEND_PKGS
    }
    apps = {"reveng_api", "reveng_worker", "reveng_desktop"}
    forbidden = siblings | apps
    violations: list[str] = []
    for path in _sources():
        for module in _top_imports(path) & forbidden:
            violations.append(f"{path.name}: {module}")
    assert not violations, f"forbidden imports: {violations}"
