"""Engineering configuration loader (REVENG_ENG_* only)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

DEFAULTS: dict[str, Any] = {
    "python_version": "3.12",
    "transitional_desktop": True,
    "proto_dir": "proto",
    "codegen_output_dir": "libs/reveng-codegen/src/reveng_codegen/generated",
}


@dataclass
class EngConfig:
    values: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    tool = data.get("tool", {}).get("reveng", {})
    return dict(tool) if isinstance(tool, dict) else {}


def _env_overrides() -> dict[str, Any]:
    out: dict[str, Any] = {}
    prefix = "REVENG_ENG_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            out[key[len(prefix):].lower()] = value
    return out


def load_config(repo_root: Path, cli_overrides: dict[str, Any] | None = None) -> EngConfig:
    """Load config with precedence: defaults < pyproject < env < local < cli."""
    merged: dict[str, Any] = dict(DEFAULTS)
    merged.update(_load_toml(repo_root / "pyproject.toml"))
    merged.update(_env_overrides())
    merged.update(_load_toml(repo_root / ".reveng.local.toml"))
    if cli_overrides:
        merged.update({k: v for k, v in cli_overrides.items() if v is not None})
    return EngConfig(values=merged)


def find_repo_root(start: Path | None = None) -> Path:
    cur = (start or Path.cwd()).resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / "pyproject.toml").is_file() and (candidate / "docs" / "engineering").is_dir():
            return candidate
    return cur
