"""reveng-validate — repository validation CLI."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reveng_config import find_repo_root, load_config
from reveng_errors import EngError, err
from reveng_logging import get_logger
from reveng_types import EngineeringEvent

logger = get_logger("reveng-validate")

REQUIRED_TOP_LEVEL = [
    "apps",
    "packages",
    "libs",
    "tools",
    "scripts",
    "proto",
    "docker",
    "tests",
    "docs",
    ".github",
]

REQUIRED_PACKAGES = [
    "core-substrate",
    "domain-producers",
    "pass-engine",
    "storage-evidence",
    "reasoning",
    "knowledge-graph",
    "investigation",
    "reporting",
    "plugin-sdk",
    "public-api",
    "deployment",
    "observability",
    "security",
    "platform-validation",
]

REQUIRED_LIBS = [
    "reveng-types",
    "reveng-errors",
    "reveng-logging",
    "reveng-config",
    "reveng-testing",
    "reveng-codegen",
]

REQUIRED_TOOLS = [
    "bootstrap",
    "repo_validate",
    "codegen",
    "workspace_build",
    "release_cut",
]

REQUIRED_APPS = [
    "reveng-desktop",
    "reveng-api",
    "reveng-worker",
]

TOOL_ENTRYPOINTS = {
    "reveng-bootstrap": "tools/bootstrap",
    "reveng-validate": "tools/repo_validate",
    "reveng-codegen": "tools/codegen",
    "reveng-workspace-build": "tools/workspace_build",
    "reveng-release-cut": "tools/release_cut",
}

FORBIDDEN_LIB_PREFIXES = ("reveng_api", "reveng_worker", "reveng_desktop")
PACKAGE_IMPORT_PREFIX = "reveng_"

# The core substrate is the shared foundation every implementation package builds
# upon (Engineering Phase 003). It is the single universally-allowed cross-package
# dependency; all other package-to-package edges remain forbidden by default.
SUBSTRATE_PACKAGE = "reveng_core_substrate"

# Explicitly allowlisted package-to-package edges beyond the universal substrate
# dependency. Keyed by the importing package module; values are the package
# modules it may import. Each edge is opened by a specific Engineering Phase and
# must be justified there; the default remains deny.
ALLOWED_PACKAGE_EDGES: dict[str, set[str]] = {
    # Engineering Phase 005: the pass engine coordinates passes over normalized
    # artifacts produced by the domain-producers package.
    "reveng_pass_engine": {"reveng_domain_producers"},
    # Engineering Phase 007: the evidence store references canonical IR entities
    # by identifier.
    "reveng_storage_evidence": {"reveng_intermediate_representation"},
    # Engineering Phase 008: static analysis consumes artifacts, runs deterministic
    # passes, produces canonical IR, and emits evidence.
    "reveng_static_analysis": {
        "reveng_domain_producers",
        "reveng_pass_engine",
        "reveng_intermediate_representation",
        "reveng_storage_evidence",
    },
    # Engineering Phase 009: the knowledge graph consumes canonical IR and
    # evidence to build a deterministic, immutable semantic graph.
    "reveng_knowledge_graph": {
        "reveng_intermediate_representation",
        "reveng_storage_evidence",
    },
    # Engineering Phase 010: the reasoning engine derives deterministic, explainable
    # inferences from the knowledge graph and the evidence store.
    "reveng_reasoning": {
        "reveng_knowledge_graph",
        "reveng_storage_evidence",
    },
    # Engineering Phase 011: the investigation engine groups inferences, graph, and
    # evidence into deterministic, immutable investigation cases.
    "reveng_investigation": {
        "reveng_reasoning",
        "reveng_knowledge_graph",
        "reveng_storage_evidence",
    },
    # Engineering Phase 012: reporting transforms investigation cases (and their
    # referenced findings/inferences/evidence/graph) into deterministic reports.
    "reveng_reporting": {
        "reveng_investigation",
        "reveng_reasoning",
        "reveng_knowledge_graph",
        "reveng_storage_evidence",
    },
    # Engineering Phase 013: the plugin SDK is intentionally the only package
    # permitted to integrate with every backend subsystem, exposing extension
    # points without bypassing the platform managers.
    "reveng_plugin_sdk": {
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
    },
}


@dataclass
class RuleResult:
    rule_id: str
    ok: bool
    message: str
    context: dict[str, Any] = field(default_factory=dict)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_layout_001(repo: Path, transitional: bool) -> RuleResult:
    missing = [name for name in REQUIRED_TOP_LEVEL if not (repo / name).exists()]
    if transitional and "apps" in missing and (repo / "src").is_dir():
        missing = [m for m in missing if m != "apps"]
    if missing:
        return RuleResult(
            "VAL.LAYOUT.001",
            False,
            "required top-level directories missing",
            {"missing": missing},
        )
    for app in REQUIRED_APPS:
        app_path = repo / "apps" / app
        if not app_path.is_dir():
            if transitional and app == "reveng-desktop" and (repo / "src").is_dir():
                continue
            return RuleResult(
                "VAL.LAYOUT.001",
                False,
                f"required app missing: {app}",
                {"app": app},
            )
    return RuleResult("VAL.LAYOUT.001", True, "top-level layout present")


def check_layout_002(repo: Path) -> RuleResult:
    bad: list[str] = []
    for name in REQUIRED_PACKAGES:
        pkg = repo / "packages" / name
        readme = pkg / "README.md"
        if not pkg.is_dir():
            bad.append(f"missing:{name}")
            continue
        if not readme.is_file():
            bad.append(f"no-readme:{name}")
            continue
        text = _read_text(readme)
        if "Owner" not in text and "Implementation Specification" not in text:
            bad.append(f"no-ownership-marker:{name}")
        if not (pkg / "pyproject.toml").is_file():
            bad.append(f"no-pyproject:{name}")
    if bad:
        return RuleResult(
            "VAL.LAYOUT.002",
            False,
            "package ownership reservations incomplete",
            {"issues": bad},
        )
    return RuleResult("VAL.LAYOUT.002", True, "package ownership markers present")


def _iter_python_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return [p for p in root.rglob("*.py") if ".venv" not in p.parts and "__pycache__" not in p.parts]


def _imported_modules(path: Path) -> list[str]:
    try:
        tree = ast.parse(_read_text(path), filename=str(path))
    except SyntaxError:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module.split(".")[0])
    return names


def check_dep_001(repo: Path) -> RuleResult:
    """Enforce import boundaries for libs/packages/tools engineering code.

    Layering policy:

    * ``libs/*`` may import only other libs (never packages, apps, or tools).
    * ``packages/*`` may import any lib, generated proto stubs, and
      ``packages/core-substrate`` (the shared foundation). Any *other*
      package-to-package edge is forbidden by default; a specific edge may be
      opened by adding it to ``ALLOWED_PACKAGE_EDGES`` (importer -> imported),
      which a future Engineering Phase does when a dependency is justified.
    * ``packages/core-substrate`` is special: it may import libs only and MUST
      NOT import any sibling package.
    * ``apps/*`` may import packages and libs; ``tools/*`` rules are unchanged.
    """
    violations: list[str] = []

    package_dirs = {p.name: p for p in (repo / "packages").iterdir() if p.is_dir()} if (repo / "packages").is_dir() else {}
    package_imports = {f"reveng_{n.replace('-', '_')}" for n in package_dirs}

    # libs must not import packages/apps/tools
    for lib in REQUIRED_LIBS:
        lib_root = repo / "libs" / lib / "src"
        for py in _iter_python_files(lib_root):
            for mod in _imported_modules(py):
                if mod.startswith("reveng_") and mod in package_imports:
                    violations.append(f"{py.relative_to(repo)}: lib imports package {mod}")
                if mod in {"reveng_api", "reveng_worker", "reveng_desktop"}:
                    violations.append(f"{py.relative_to(repo)}: lib imports app {mod}")
                if mod.startswith("reveng_") and mod in {
                    "reveng_bootstrap",
                    "reveng_validate",
                    "reveng_codegen_tool",
                    "reveng_workspace_build",
                    "reveng_release_cut",
                }:
                    violations.append(f"{py.relative_to(repo)}: lib imports tool {mod}")

    # packages must not import sibling packages or apps, except the shared
    # core-substrate foundation and any explicitly allowlisted edge.
    for name, pkg_dir in package_dirs.items():
        self_import = f"reveng_{name.replace('-', '_')}"
        allowed_edges = ALLOWED_PACKAGE_EDGES.get(self_import, set())
        for py in _iter_python_files(pkg_dir / "src"):
            for mod in _imported_modules(py):
                if (
                    mod in package_imports
                    and mod != self_import
                    and mod != SUBSTRATE_PACKAGE
                    and mod not in allowed_edges
                ):
                    violations.append(f"{py.relative_to(repo)}: sibling package import {mod}")
                if mod in {"reveng_api", "reveng_worker", "reveng_desktop"}:
                    violations.append(f"{py.relative_to(repo)}: package imports app {mod}")

    if violations:
        return RuleResult(
            "VAL.DEP.001",
            False,
            "forbidden import edges detected",
            {"violations": violations[:50]},
        )
    return RuleResult("VAL.DEP.001", True, "import boundaries satisfied")


def check_dep_002(repo: Path) -> RuleResult:
    lock = repo / "uv.lock"
    if not lock.is_file():
        return RuleResult("VAL.DEP.002", False, "uv.lock missing", {})
    try:
        proc = subprocess.run(
            ["uv", "lock", "--check"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return RuleResult("VAL.DEP.002", False, "uv not found", {})
    if proc.returncode != 0:
        return RuleResult(
            "VAL.DEP.002",
            False,
            "uv.lock out of sync",
            {"stderr": proc.stderr.strip()[:500]},
        )
    return RuleResult("VAL.DEP.002", True, "uv.lock present and in sync")


def check_py_001(repo: Path) -> RuleResult:
    path = repo / ".python-version"
    if not path.is_file():
        return RuleResult("VAL.PY.001", False, ".python-version missing", {})
    value = path.read_text(encoding="utf-8").strip()
    if value != "3.12":
        return RuleResult(
            "VAL.PY.001",
            False,
            ".python-version must be 3.12",
            {"value": value},
        )
    return RuleResult("VAL.PY.001", True, ".python-version is 3.12")


def check_codegen_001(repo: Path) -> RuleResult:
    from reveng_codegen import has_proto_sources, list_proto_files

    if not has_proto_sources(repo):
        return RuleResult(
            "VAL.CODEGEN.001",
            True,
            "no proto sources; codegen verify-dirty skipped",
            {"proto_files": 0},
        )
    # When protos exist, generated marker package must exist
    gen = repo / "libs" / "reveng-codegen" / "src" / "reveng_codegen" / "generated" / "__init__.py"
    if not gen.is_file():
        return RuleResult(
            "VAL.CODEGEN.001",
            False,
            "proto sources present but generated package missing",
            {"protos": [str(p.relative_to(repo)) for p in list_proto_files(repo)]},
        )
    return RuleResult("VAL.CODEGEN.001", True, "codegen outputs present for proto sources")


def check_tool_001(repo: Path) -> RuleResult:
    missing: list[str] = []
    for entry, rel in TOOL_ENTRYPOINTS.items():
        tool_dir = repo / rel
        pyproject = tool_dir / "pyproject.toml"
        if not pyproject.is_file():
            missing.append(f"{entry}: missing {rel}/pyproject.toml")
            continue
        text = _read_text(pyproject)
        if entry not in text:
            missing.append(f"{entry}: not registered in {rel}/pyproject.toml")
    for name in REQUIRED_TOOLS:
        if not (repo / "tools" / name).is_dir():
            missing.append(f"tools/{name} missing")
    for name in REQUIRED_LIBS:
        if not (repo / "libs" / name).is_dir():
            missing.append(f"libs/{name} missing")
    if missing:
        return RuleResult(
            "VAL.TOOL.001",
            False,
            "engineering tool entrypoints incomplete",
            {"missing": missing},
        )
    return RuleResult("VAL.TOOL.001", True, "engineering tools registered")


def check_doc_001(repo: Path) -> RuleResult:
    path = repo / "docs" / "engineering" / "ENGINEERING_PHASE_001_REPOSITORY_FOUNDATION.md"
    if not path.is_file():
        return RuleResult("VAL.DOC.001", False, "Engineering Phase 001 document missing", {})
    return RuleResult("VAL.DOC.001", True, "Engineering Phase 001 document present")


def run_validation(repo: Path) -> tuple[bool, list[RuleResult], list[EngError]]:
    cfg = load_config(repo)
    transitional = bool(cfg.get("transitional_desktop", True))
    results = [
        check_layout_001(repo, transitional),
        check_layout_002(repo),
        check_dep_001(repo),
        check_dep_002(repo),
        check_py_001(repo),
        check_codegen_001(repo),
        check_tool_001(repo),
        check_doc_001(repo),
    ]
    errors = [
        err(r.rule_id, r.message, **r.context)
        for r in results
        if not r.ok
    ]
    return (len(errors) == 0, results, errors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reveng-validate", description="Validate RevENG repository engineering invariants")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    parser.add_argument("--repo", type=Path, default=None, help="Repository root")
    args = parser.parse_args(argv)

    repo = find_repo_root(args.repo) if args.repo is None else args.repo.resolve()
    ok, results, errors = run_validation(repo)

    summary: dict[str, Any] = {
        "ok": ok,
        "tool": "reveng-validate",
        "event": EngineeringEvent.VALIDATION_PASSED.value if ok else EngineeringEvent.VALIDATION_FAILED.value,
        "errors": [e.to_dict() for e in errors],
        "data": {
            "repo": str(repo),
            "results": [
                {"rule_id": r.rule_id, "ok": r.ok, "message": r.message, "context": r.context}
                for r in results
            ],
        },
    }

    if ok:
        logger.info("validation passed", event=EngineeringEvent.VALIDATION_PASSED.value)
    else:
        logger.error(
            "validation failed",
            event=EngineeringEvent.VALIDATION_FAILED.value,
            error_count=len(errors),
        )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for r in results:
            status = "PASS" if r.ok else "FAIL"
            print(f"{status} {r.rule_id}: {r.message}")
        print("OK" if ok else "FAILED")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
