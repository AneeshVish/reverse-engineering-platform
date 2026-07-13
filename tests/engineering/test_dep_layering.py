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


def test_storage_may_import_ir(tmp_path: Path) -> None:
    # Engineering Phase 007 allowlists storage-evidence -> intermediate-representation.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "intermediate-representation", "y = 2\n")
    _package(
        tmp_path,
        "storage-evidence",
        "from reveng_intermediate_representation import IRIdentifier\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_storage_edge_is_specific(tmp_path: Path) -> None:
    # storage may not reach producers or pass-engine, and IR may not import storage.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "domain-producers", "d = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    # IR -> storage (reverse edge, forbidden)
    _package(tmp_path, "intermediate-representation", "import reveng_storage_evidence\n")
    _package(
        tmp_path,
        "storage-evidence",
        "import reveng_domain_producers\nimport reveng_pass_engine\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_domain_producers" in v for v in violations)
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
    assert any("sibling package import reveng_storage_evidence" in v for v in violations)


def test_static_analysis_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 008 allowlists static-analysis -> {producers, pass-engine, IR, storage}.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "domain-producers", "d = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    _package(tmp_path, "intermediate-representation", "i = 1\n")
    _package(tmp_path, "storage-evidence", "s = 1\n")
    _package(
        tmp_path,
        "static-analysis",
        "import reveng_domain_producers\n"
        "import reveng_pass_engine\n"
        "import reveng_intermediate_representation\n"
        "import reveng_storage_evidence\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_static_analysis_forbidden_edges(tmp_path: Path) -> None:
    # static may not reach reasoning/investigation/plugins; and nothing imports static.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "reasoning", "r = 1\n")
    _package(tmp_path, "investigation", "n = 1\n")
    _package(tmp_path, "plugin-sdk", "g = 1\n")
    # reverse edges (forbidden): nothing lower may import static-analysis
    _package(tmp_path, "pass-engine", "import reveng_static_analysis\n")
    _package(tmp_path, "intermediate-representation", "import reveng_static_analysis\n")
    _package(
        tmp_path,
        "static-analysis",
        "import reveng_reasoning\nimport reveng_investigation\nimport reveng_plugin_sdk\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_reasoning" in v for v in violations)
    assert any("sibling package import reveng_investigation" in v for v in violations)
    assert any("sibling package import reveng_plugin_sdk" in v for v in violations)
    assert any("sibling package import reveng_static_analysis" in v for v in violations)


def test_knowledge_graph_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 009 allowlists knowledge-graph -> {IR, storage}.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "intermediate-representation", "i = 1\n")
    _package(tmp_path, "storage-evidence", "s = 1\n")
    _package(
        tmp_path,
        "knowledge-graph",
        "import reveng_intermediate_representation\nimport reveng_storage_evidence\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_knowledge_graph_forbidden_edges(tmp_path: Path) -> None:
    # graph may not reach pass-engine/static/reasoning/investigation; nothing lower imports graph.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    _package(tmp_path, "static-analysis", "a = 1\n")
    _package(tmp_path, "reasoning", "r = 1\n")
    _package(tmp_path, "investigation", "n = 1\n")
    # reverse edges (forbidden): nothing lower may import knowledge-graph
    _package(tmp_path, "intermediate-representation", "import reveng_knowledge_graph\n")
    _package(tmp_path, "storage-evidence", "import reveng_knowledge_graph\n")
    _package(
        tmp_path,
        "knowledge-graph",
        "import reveng_pass_engine\n"
        "import reveng_static_analysis\n"
        "import reveng_reasoning\n"
        "import reveng_investigation\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
    assert any("sibling package import reveng_static_analysis" in v for v in violations)
    assert any("sibling package import reveng_reasoning" in v for v in violations)
    assert any("sibling package import reveng_investigation" in v for v in violations)
    assert any("sibling package import reveng_knowledge_graph" in v for v in violations)


def test_reasoning_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 010 allowlists reasoning -> {knowledge-graph, storage}.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "knowledge-graph", "k = 1\n")
    _package(tmp_path, "storage-evidence", "s = 1\n")
    _package(
        tmp_path,
        "reasoning",
        "import reveng_knowledge_graph\nimport reveng_storage_evidence\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_reasoning_forbidden_edges(tmp_path: Path) -> None:
    # reasoning may not reach static/pass-engine/producers; nothing lower imports reasoning.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "static-analysis", "a = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    _package(tmp_path, "domain-producers", "d = 1\n")
    # reverse edges (forbidden): nothing lower may import reasoning
    _package(tmp_path, "knowledge-graph", "import reveng_reasoning\n")
    _package(tmp_path, "storage-evidence", "import reveng_reasoning\n")
    _package(
        tmp_path,
        "reasoning",
        "import reveng_static_analysis\n"
        "import reveng_pass_engine\n"
        "import reveng_domain_producers\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_static_analysis" in v for v in violations)
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
    assert any("sibling package import reveng_domain_producers" in v for v in violations)
    assert any("sibling package import reveng_reasoning" in v for v in violations)


def test_investigation_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 011 allowlists investigation -> {reasoning, knowledge-graph, storage}.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "reasoning", "r = 1\n")
    _package(tmp_path, "knowledge-graph", "k = 1\n")
    _package(tmp_path, "storage-evidence", "s = 1\n")
    _package(
        tmp_path,
        "investigation",
        "import reveng_reasoning\nimport reveng_knowledge_graph\nimport reveng_storage_evidence\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_investigation_forbidden_edges(tmp_path: Path) -> None:
    # investigation may not reach static/pass-engine/producers; nothing lower imports it.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "static-analysis", "a = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    _package(tmp_path, "domain-producers", "d = 1\n")
    # reverse edges (forbidden): nothing lower may import investigation
    _package(tmp_path, "reasoning", "import reveng_investigation\n")
    _package(tmp_path, "knowledge-graph", "import reveng_investigation\n")
    _package(tmp_path, "storage-evidence", "import reveng_investigation\n")
    _package(
        tmp_path,
        "investigation",
        "import reveng_static_analysis\n"
        "import reveng_pass_engine\n"
        "import reveng_domain_producers\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_static_analysis" in v for v in violations)
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
    assert any("sibling package import reveng_domain_producers" in v for v in violations)
    assert any("sibling package import reveng_investigation" in v for v in violations)


def test_reporting_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 012 allowlists reporting -> {investigation, reasoning, graph, storage}.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "investigation", "n = 1\n")
    _package(tmp_path, "reasoning", "r = 1\n")
    _package(tmp_path, "knowledge-graph", "k = 1\n")
    _package(tmp_path, "storage-evidence", "s = 1\n")
    _package(
        tmp_path,
        "reporting",
        "import reveng_investigation\n"
        "import reveng_reasoning\n"
        "import reveng_knowledge_graph\n"
        "import reveng_storage_evidence\n",
    )
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_reporting_forbidden_edges(tmp_path: Path) -> None:
    # reporting may not reach static/pass-engine/producers; nothing lower imports it.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "static-analysis", "a = 1\n")
    _package(tmp_path, "pass-engine", "p = 1\n")
    _package(tmp_path, "domain-producers", "d = 1\n")
    # reverse edges (forbidden): nothing lower may import reporting
    _package(tmp_path, "investigation", "import reveng_reporting\n")
    _package(tmp_path, "reasoning", "import reveng_reporting\n")
    _package(tmp_path, "knowledge-graph", "import reveng_reporting\n")
    _package(tmp_path, "storage-evidence", "import reveng_reporting\n")
    _package(
        tmp_path,
        "reporting",
        "import reveng_static_analysis\n"
        "import reveng_pass_engine\n"
        "import reveng_domain_producers\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_static_analysis" in v for v in violations)
    assert any("sibling package import reveng_pass_engine" in v for v in violations)
    assert any("sibling package import reveng_domain_producers" in v for v in violations)
    assert any("sibling package import reveng_reporting" in v for v in violations)


_PLUGIN_BACKENDS = (
    "domain-producers",
    "pass-engine",
    "intermediate-representation",
    "storage-evidence",
    "static-analysis",
    "knowledge-graph",
    "reasoning",
    "investigation",
    "reporting",
)


def test_plugin_sdk_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 013 allowlists plugin-sdk -> every backend package.
    _package(tmp_path, "core-substrate", "x = 1\n")
    for name in _PLUGIN_BACKENDS:
        _package(tmp_path, name, "v = 1\n")
    imports = "".join(f"import reveng_{n.replace('-', '_')}\n" for n in _PLUGIN_BACKENDS)
    _package(tmp_path, "plugin-sdk", imports)
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_plugin_sdk_forbidden_edges(tmp_path: Path) -> None:
    # No backend may import the plugin SDK, and the SDK may not reach apps or the
    # upper-tier reserved packages (public-api / deployment / observability).
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "public-api", "a = 1\n")
    _package(tmp_path, "deployment", "d = 1\n")
    _package(tmp_path, "observability", "o = 1\n")
    # reverse edges (forbidden): backends may not import the plugin SDK
    _package(tmp_path, "reporting", "import reveng_plugin_sdk\n")
    _package(tmp_path, "reasoning", "import reveng_plugin_sdk\n")
    _package(
        tmp_path,
        "plugin-sdk",
        "import reveng_public_api\n"
        "import reveng_deployment\n"
        "import reveng_observability\n"
        "import reveng_desktop\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_public_api" in v for v in violations)
    assert any("sibling package import reveng_deployment" in v for v in violations)
    assert any("sibling package import reveng_observability" in v for v in violations)
    assert any("imports app reveng_desktop" in v for v in violations)
    assert any("sibling package import reveng_plugin_sdk" in v for v in violations)


_PUBLIC_API_BACKENDS = (
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
)


def test_public_api_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 014 allowlists public-api -> every backend package plus
    # the plugin SDK (for read-only plugin listing).
    _package(tmp_path, "core-substrate", "x = 1\n")
    for name in _PUBLIC_API_BACKENDS:
        _package(tmp_path, name, "v = 1\n")
    imports = "".join(f"import reveng_{n.replace('-', '_')}\n" for n in _PUBLIC_API_BACKENDS)
    _package(tmp_path, "public-api", imports)
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_public_api_forbidden_edges(tmp_path: Path) -> None:
    # No backend or the plugin SDK may import public-api, and public-api may not
    # reach apps or the other upper-tier reserved siblings (deployment /
    # observability / security / platform-validation).
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "deployment", "d = 1\n")
    _package(tmp_path, "observability", "o = 1\n")
    _package(tmp_path, "security", "s = 1\n")
    _package(tmp_path, "platform-validation", "p = 1\n")
    # reverse edges (forbidden): nothing lower, including the plugin SDK, may
    # import public-api
    _package(tmp_path, "reporting", "import reveng_public_api\n")
    _package(tmp_path, "plugin-sdk", "import reveng_public_api\n")
    _package(
        tmp_path,
        "public-api",
        "import reveng_deployment\n"
        "import reveng_observability\n"
        "import reveng_security\n"
        "import reveng_platform_validation\n"
        "import reveng_desktop\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_deployment" in v for v in violations)
    assert any("sibling package import reveng_observability" in v for v in violations)
    assert any("sibling package import reveng_security" in v for v in violations)
    assert any("sibling package import reveng_platform_validation" in v for v in violations)
    assert any("imports app reveng_desktop" in v for v in violations)
    assert any("sibling package import reveng_public_api" in v for v in violations)


def test_desktop_sdk_allowed_edges(tmp_path: Path) -> None:
    # Engineering Phase 015 allowlists desktop-sdk -> public-api only.
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "public-api", "v = 1\n")
    _package(tmp_path, "desktop-sdk", "import reveng_public_api\n")
    result = check_dep_001(tmp_path)
    assert result.ok, result.context


def test_desktop_sdk_forbidden_edges(tmp_path: Path) -> None:
    # Nothing may import desktop-sdk (nothing lower depends on it), and
    # desktop-sdk may not reach apps or the other upper-tier reserved
    # siblings (deployment / observability / security / platform-validation).
    _package(tmp_path, "core-substrate", "x = 1\n")
    _package(tmp_path, "deployment", "d = 1\n")
    _package(tmp_path, "observability", "o = 1\n")
    _package(tmp_path, "security", "s = 1\n")
    _package(tmp_path, "platform-validation", "p = 1\n")
    _package(tmp_path, "public-api", "import reveng_desktop_sdk\n")  # forbidden reverse edge
    _package(
        tmp_path,
        "desktop-sdk",
        "import reveng_deployment\n"
        "import reveng_observability\n"
        "import reveng_security\n"
        "import reveng_platform_validation\n"
        "import reveng_desktop\n"
        "import reveng_api\n",
    )
    result = check_dep_001(tmp_path)
    assert not result.ok
    violations = result.context["violations"]
    assert any("sibling package import reveng_deployment" in v for v in violations)
    assert any("sibling package import reveng_observability" in v for v in violations)
    assert any("sibling package import reveng_security" in v for v in violations)
    assert any("sibling package import reveng_platform_validation" in v for v in violations)
    assert any("imports app reveng_desktop" in v for v in violations)
    assert any("imports app reveng_api" in v for v in violations)
    assert any("sibling package import reveng_desktop_sdk" in v for v in violations)
