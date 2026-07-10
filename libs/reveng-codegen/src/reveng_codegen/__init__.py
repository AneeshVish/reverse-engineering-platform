"""Codegen path contracts for engineering scaffolding."""

from __future__ import annotations

from pathlib import Path

__version__ = "0.1.0"

GENERATED_PACKAGE = "reveng_codegen.generated"
GENERATED_MARKER = "__generated_by__"
GENERATOR_NAME = "reveng-codegen"


def proto_dir(repo_root: Path) -> Path:
    return repo_root / "proto"


def output_dir(repo_root: Path) -> Path:
    return repo_root / "libs" / "reveng-codegen" / "src" / "reveng_codegen" / "generated"


def list_proto_files(repo_root: Path) -> list[Path]:
    root = proto_dir(repo_root)
    if not root.is_dir():
        return []
    return sorted(root.rglob("*.proto"))


def has_proto_sources(repo_root: Path) -> bool:
    return bool(list_proto_files(repo_root))
