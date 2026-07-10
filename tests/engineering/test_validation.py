"""Engineering tests: validation tool."""

from __future__ import annotations

from reveng_config import find_repo_root
from reveng_validate.cli import run_validation


def test_validation_passes_on_workspace() -> None:
    repo = find_repo_root()
    ok, results, errors = run_validation(repo)
    assert ok, [e.to_dict() for e in errors]
    assert all(r.ok for r in results)
