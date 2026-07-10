"""reveng-release-cut — SemVer tag creation CLI."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from reveng_config import find_repo_root
from reveng_errors import err
from reveng_logging import get_logger
from reveng_types import EngineeringEvent

logger = get_logger("reveng-release-cut")

SEMVER_RE = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def normalize_tag(version: str) -> str:
    version = version.strip()
    if not version.startswith("v"):
        return f"v{version}"
    return version


def is_valid_semver(version: str) -> bool:
    return bool(SEMVER_RE.match(version.strip()))


def _is_clean(repo: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout.strip() == "", proc.stdout)


def release_cut(repo: Path, version: str, *, dry_run: bool = False) -> dict[str, Any]:
    if not is_valid_semver(version):
        error = err("ENG.RELEASE.INVALID_SEMVER", "version is not valid SemVer", version=version)
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-release-cut",
            "event": EngineeringEvent.RELEASE_TAGGED.value,
            "errors": [error.to_dict()],
            "data": {},
        }

    tag = normalize_tag(version)

    clean, status = _is_clean(repo)
    if not clean:
        error = err("ENG.RELEASE.DIRTY_TREE", "repository working tree is not clean", status=status[:500])
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-release-cut",
            "event": EngineeringEvent.RELEASE_TAGGED.value,
            "errors": [error.to_dict()],
            "data": {"tag": tag},
        }

    if dry_run:
        logger.info("release cut dry-run ok", event=EngineeringEvent.RELEASE_TAGGED.value, tag=tag)
        return {
            "ok": True,
            "tool": "reveng-release-cut",
            "event": EngineeringEvent.RELEASE_TAGGED.value,
            "errors": [],
            "data": {"tag": tag, "dry_run": True},
        }

    existing = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if existing.returncode == 0:
        error = err("ENG.RELEASE.TAG_EXISTS", "tag already exists", tag=tag)
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-release-cut",
            "event": EngineeringEvent.RELEASE_TAGGED.value,
            "errors": [error.to_dict()],
            "data": {"tag": tag},
        }

    proc = subprocess.run(
        ["git", "tag", "-a", tag, "-m", f"Release {tag}"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        error = err(
            "ENG.RELEASE.TAG_FAILED",
            "git tag failed",
            stderr=proc.stderr.strip()[:500],
            tag=tag,
        )
        logger.error(error.message, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-release-cut",
            "event": EngineeringEvent.RELEASE_TAGGED.value,
            "errors": [error.to_dict()],
            "data": {"tag": tag},
        }

    logger.info("release tagged", event=EngineeringEvent.RELEASE_TAGGED.value, tag=tag)
    return {
        "ok": True,
        "tool": "reveng-release-cut",
        "event": EngineeringEvent.RELEASE_TAGGED.value,
        "errors": [],
        "data": {"tag": tag, "dry_run": False},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reveng-release-cut", description="Create annotated SemVer release tag")
    parser.add_argument("version", help="SemVer version (e.g. 0.1.0 or v0.1.0)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    repo = find_repo_root(args.repo) if args.repo is None else args.repo.resolve()
    summary = release_cut(repo, args.version, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("Release OK" if summary["ok"] else "Release FAILED")
        if summary.get("data", {}).get("tag"):
            print(f"tag: {summary['data']['tag']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
