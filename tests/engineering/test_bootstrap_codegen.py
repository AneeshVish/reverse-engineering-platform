"""Engineering tests: bootstrap and codegen scaffolding."""

from __future__ import annotations

from reveng_codegen import has_proto_sources, list_proto_files, proto_dir
from reveng_codegen_tool.cli import run_codegen
from reveng_config import find_repo_root
from reveng_workspace_build.cli import discover_members, validate_graph


def test_proto_dir_exists_without_sources() -> None:
    repo = find_repo_root()
    assert proto_dir(repo).is_dir()
    assert has_proto_sources(repo) is False
    assert list_proto_files(repo) == []


def test_codegen_idle_without_proto() -> None:
    repo = find_repo_root()
    summary = run_codegen(repo, verify_dirty=False)
    assert summary["ok"] is True
    assert summary["data"]["proto_present"] is False


def test_workspace_members_discoverable() -> None:
    repo = find_repo_root()
    members = discover_members(repo)
    names = {m["name"] for m in members}
    assert "reveng-types" in names
    assert "reveng-bootstrap" in names
    assert "reveng-core-substrate" in names
    issues = validate_graph(members)
    assert issues == []


def test_release_semver_validation() -> None:
    from reveng_release_cut.cli import is_valid_semver, release_cut

    assert is_valid_semver("0.1.0")
    assert is_valid_semver("v1.2.3")
    assert not is_valid_semver("1.2")
    repo = find_repo_root()
    # dry-run may fail if dirty; only check invalid semver path
    summary = release_cut(repo, "not-a-version", dry_run=True)
    assert summary["ok"] is False
    assert summary["errors"][0]["code"] == "ENG.RELEASE.INVALID_SEMVER"
