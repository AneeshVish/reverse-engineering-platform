"""reveng-workspace-build — build orchestration CLI."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

from reveng_config import find_repo_root
from reveng_errors import err
from reveng_logging import get_logger
from reveng_types import EngineeringEvent

logger = get_logger("reveng-workspace-build")


def discover_members(repo: Path) -> list[dict[str, str]]:
    root_py = repo / "pyproject.toml"
    with root_py.open("rb") as fh:
        data = tomllib.load(fh)
    members = data.get("tool", {}).get("uv", {}).get("workspace", {}).get("members", [])
    discovered: list[dict[str, str]] = []
    for pattern in members:
        if pattern.endswith("/*"):
            parent = repo / pattern[:-2]
            if not parent.is_dir():
                continue
            children = sorted(p for p in parent.iterdir() if (p / "pyproject.toml").is_file())
        else:
            child = repo / pattern
            children = [child] if (child / "pyproject.toml").is_file() else []
        for child in children:
            with (child / "pyproject.toml").open("rb") as fh:
                meta = tomllib.load(fh)
            name = meta.get("project", {}).get("name", child.name)
            discovered.append({"path": str(child.relative_to(repo)), "name": name})
    return discovered


def validate_graph(members: list[dict[str, str]]) -> list[str]:
    names = {m["name"] for m in members}
    issues: list[str] = []
    required = {
        "reveng-types",
        "reveng-errors",
        "reveng-logging",
        "reveng-config",
        "reveng-testing",
        "reveng-codegen",
        "reveng-bootstrap",
        "reveng-validate",
        "reveng-codegen-cli",
        "reveng-workspace-build",
        "reveng-release-cut",
    }
    missing = sorted(required - names)
    if missing:
        issues.append(f"missing workspace members: {missing}")
    return issues


def run_build(repo: Path, *, dry_run: bool = False) -> dict[str, Any]:
    members = discover_members(repo)
    issues = validate_graph(members)
    if issues:
        error = err("ENG.BUILD.GRAPH_INVALID", "package graph validation failed", issues=issues)
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-workspace-build",
            "event": EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
            "errors": [error.to_dict()],
            "data": {"members": members},
        }

    if dry_run:
        logger.info(
            "workspace build dry-run ok",
            event=EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
            member_count=len(members),
        )
        return {
            "ok": True,
            "tool": "reveng-workspace-build",
            "event": EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
            "errors": [],
            "data": {"members": members, "dry_run": True},
        }

    proc = subprocess.run(
        ["uv", "build", "--all"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        error = err(
            "ENG.BUILD.UV_BUILD_FAILED",
            "uv build --all failed",
            stderr=proc.stderr.strip()[:800],
            stdout=proc.stdout.strip()[:400],
        )
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-workspace-build",
            "event": EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
            "errors": [error.to_dict()],
            "data": {"members": members},
        }

    logger.info(
        "workspace build completed",
        event=EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
        member_count=len(members),
    )
    return {
        "ok": True,
        "tool": "reveng-workspace-build",
        "event": EngineeringEvent.WORKSPACE_BUILD_COMPLETED.value,
        "errors": [],
        "data": {"members": members, "dry_run": False},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reveng-workspace-build", description="Build RevENG workspace packages")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true", help="Validate graph without building")
    args = parser.parse_args(argv)

    repo = find_repo_root(args.repo) if args.repo is None else args.repo.resolve()
    summary = run_build(repo, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("Build OK" if summary["ok"] else "Build FAILED")
        print(f"members: {len(summary.get('data', {}).get('members', []))}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
