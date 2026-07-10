"""Engineering test helpers."""

from __future__ import annotations

from pathlib import Path

__version__ = "0.1.0"


def repo_root_from_tests() -> Path:
    """Resolve repository root by walking up for workspace pyproject."""
    here = Path(__file__).resolve()
    for candidate in [here, *here.parents]:
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file() and (candidate / "docs" / "engineering").is_dir():
            return candidate
    raise RuntimeError("could not locate repository root")


def assert_path_exists(path: Path) -> None:
    if not path.exists():
        raise AssertionError(f"missing path: {path}")
