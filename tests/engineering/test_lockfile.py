"""Engineering tests: lockfile."""

from __future__ import annotations

from reveng_config import find_repo_root
from reveng_validate.cli import check_dep_002


def test_lockfile_present_and_synced() -> None:
    repo = find_repo_root()
    assert (repo / "uv.lock").is_file()
    result = check_dep_002(repo)
    assert result.ok, result.context
