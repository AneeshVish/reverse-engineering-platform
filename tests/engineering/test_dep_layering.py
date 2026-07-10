"""Engineering tests: package dependency layering policy.

Locks in the Engineering Phase 004 refinement to ``check_dep_001``: every package
may build upon ``packages/core-substrate``, but all other package-to-package
edges remain forbidden by default, and core-substrate itself may not import a
sibling. These assertions run against synthetic repository trees so they are
independent of the real workspace's current import graph.
"""

from __future__ import annotations

from pathlib import Path

from reveng_validate.cli import check_dep_001


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _package(repo: Path, name: str, module_body: str) -> None:
    mod = repo / "packages" / name / "src" / f"reveng_{name.replace('-', '_')}" / "mod.py"
    _write(mod, module_body)


def test_package_may_import_core_substrate(tmp_path: Path) -> None:
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "pkg-a", "from reveng_core_substrate import Application\n")
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_package_may_not_import_other_sibling(tmp_path: Path) -> None:
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "pkg-a", "import reveng_pkg_b\n")
    _package(tmp_path, "pkg-b", "y = 2\n")
    result = check_dep_001(tmp_path)
    assert not result.ok
    assert any("sibling package import reveng_pkg_b" in v for v in result.context["violations"])


def test_core_substrate_may_not_import_a_sibling(tmp_path: Path) -> None:
    _package(tmp_path, "core-substrate", "import reveng_pkg_a\n")
    _package(tmp_path, "pkg-a", "z = 3\n")
    result = check_dep_001(tmp_path)
    assert not result.ok
    assert any("sibling package import reveng_pkg_a" in v for v in result.context["violations"])


def test_package_may_not_import_app(tmp_path: Path) -> None:
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "pkg-a", "import reveng_desktop\n")
    result = check_dep_001(tmp_path)
    assert not result.ok
    assert any("imports app reveng_desktop" in v for v in result.context["violations"])


def test_allowlisted_edge_permits_specific_import(tmp_path: Path) -> None:
    # Engineering Phase 005 allowlists pass-engine -> domain-producers.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "domain-producers", "y = 2\n")
    _package(tmp_path, "pass-engine", "from reveng_domain_producers import Artifact\n")
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_allowlist_is_edge_specific_not_global(tmp_path: Path) -> None:
    # The allowlist opens exactly one edge; other imports by the same package,
    # and the reverse edge, remain forbidden.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "domain-producers", "import reveng_pass_engine\n")  # reverse edge
    _package(tmp_path, "pass-engine", "import reveng_reasoning\n")  # non-allowlisted
    _package(tmp_path, "reasoning", "z = 3\n")
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_reasoning" in v for v in violations)
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
