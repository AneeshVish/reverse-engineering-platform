"""Engineering tests: workspace layout."""

from __future__ import annotations

from reveng_testing import assert_path_exists, repo_root_from_tests

REQUIRED_TOP = [
    "apps",
    "packages",
    "libs",
    "tools",
    "scripts",
    "proto",
    "docker",
    "tests",
    "docs",
]


def test_top_level_layout() -> None:
    root = repo_root_from_tests()
    for name in REQUIRED_TOP:
        assert_path_exists(root / name)


def test_engineering_doc_present() -> None:
    root = repo_root_from_tests()
    path = root / "docs" / "engineering" / "ENGINEERING_PHASE_001_REPOSITORY_FOUNDATION.md"
    assert path.is_file()


def test_python_version_pin() -> None:
    root = repo_root_from_tests()
    assert (root / ".python-version").read_text(encoding="utf-8").strip() == "3.12"


def test_reserved_packages_exist() -> None:
    root = repo_root_from_tests()
    packages = [
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
    for name in packages:
        pkg = root / "packages" / name
        assert (pkg / "README.md").is_file()
        assert (pkg / "pyproject.toml").is_file()
        assert list((pkg / "src").rglob("__init__.py"))


def test_libs_and_tools_exist() -> None:
    root = repo_root_from_tests()
    for name in [
        "reveng-types",
        "reveng-errors",
        "reveng-logging",
        "reveng-config",
        "reveng-testing",
        "reveng-codegen",
    ]:
        assert (root / "libs" / name / "pyproject.toml").is_file()
    for name in ["bootstrap", "repo_validate", "codegen", "workspace_build", "release_cut"]:
        assert (root / "tools" / name / "pyproject.toml").is_file()


def test_transitional_src_still_present() -> None:
    """Existing application tree remains until migration step 4."""
    root = repo_root_from_tests()
    assert (root / "src").is_dir()
