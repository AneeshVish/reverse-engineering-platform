"""Engineering tests: import boundaries."""

from __future__ import annotations

from reveng_config import find_repo_root
from reveng_validate.cli import check_dep_001


def test_import_boundaries() -> None:
    repo = find_repo_root()
    result = check_dep_001(repo)
    assert result.ok, result.context
