"""reveng-bootstrap — workspace bootstrap CLI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from reveng_config import find_repo_root, load_config
from reveng_errors import err
from reveng_logging import get_logger
from reveng_types import EngineeringEvent

logger = get_logger("reveng-bootstrap")


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def _python_ok() -> tuple[bool, str]:
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 12):
        return True, f"{major}.{minor}"
    # uv can fetch 3.12; bootstrap still proceeds if uv is present
    return False, f"{major}.{minor}"


def _uv_path() -> str | None:
    return shutil.which("uv")


def bootstrap(repo: Path, *, skip_validate: bool = False, skip_pre_commit: bool = False) -> dict[str, Any]:
    cfg = load_config(repo)
    steps: list[dict[str, Any]] = []

    py_ok, py_ver = _python_ok()
    steps.append({"step": "python", "ok": True, "version": py_ver, "meets_3_12": py_ok})

    uv = _uv_path()
    if uv is None:
        error = err("ENG.BOOTSTRAP.UV_MISSING", "uv executable not found on PATH")
        logger.error(error.message, event=EngineeringEvent.BOOTSTRAP_FAILED.value, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-bootstrap",
            "event": EngineeringEvent.BOOTSTRAP_FAILED.value,
            "errors": [error.to_dict()],
            "data": {"steps": steps},
        }
    steps.append({"step": "uv", "ok": True, "path": uv})

    # Ensure pinned interpreter for workspace
    pin = _run([uv, "python", "pin", "3.12"], cwd=repo)
    steps.append({"step": "python_pin", "ok": pin.returncode == 0, "stderr": pin.stderr.strip()[:300]})

    sync = _run([uv, "sync", "--all-groups"], cwd=repo)
    if sync.returncode != 0:
        error = err(
            "ENG.BOOTSTRAP.SYNC_FAILED",
            "uv sync --all-groups failed",
            stderr=sync.stderr.strip()[:800],
        )
        logger.error(error.message, event=EngineeringEvent.BOOTSTRAP_FAILED.value, code=error.code)
        return {
            "ok": False,
            "tool": "reveng-bootstrap",
            "event": EngineeringEvent.BOOTSTRAP_FAILED.value,
            "errors": [error.to_dict()],
            "data": {"steps": steps},
        }
    steps.append({"step": "uv_sync", "ok": True})

    if not skip_pre_commit:
        pre_commit_cfg = repo / ".pre-commit-config.yaml"
        if pre_commit_cfg.is_file():
            # Install hooks via uv-run so the tool is available from the workspace
            hook = _run([uv, "run", "pre-commit", "install"], cwd=repo)
            steps.append(
                {
                    "step": "pre_commit",
                    "ok": hook.returncode == 0,
                    "stderr": hook.stderr.strip()[:300],
                }
            )
        else:
            steps.append({"step": "pre_commit", "ok": True, "skipped": True})

    # Codegen if proto sources exist
    from reveng_codegen import has_proto_sources

    if has_proto_sources(repo):
        gen = _run([uv, "run", "reveng-codegen"], cwd=repo)
        if gen.returncode != 0:
            error = err(
                "ENG.BOOTSTRAP.CODEGEN_FAILED",
                "reveng-codegen failed during bootstrap",
                stderr=gen.stderr.strip()[:800],
            )
            logger.error(error.message, event=EngineeringEvent.BOOTSTRAP_FAILED.value, code=error.code)
            return {
                "ok": False,
                "tool": "reveng-bootstrap",
                "event": EngineeringEvent.BOOTSTRAP_FAILED.value,
                "errors": [error.to_dict()],
                "data": {"steps": steps, "config": cfg.values},
            }
        steps.append({"step": "codegen", "ok": True})
    else:
        steps.append({"step": "codegen", "ok": True, "skipped": True, "reason": "no proto sources"})

    if not skip_validate:
        val = _run([uv, "run", "reveng-validate", "--json"], cwd=repo)
        if val.returncode != 0:
            error = err(
                "ENG.BOOTSTRAP.VALIDATE_FAILED",
                "reveng-validate failed during bootstrap",
                stdout=val.stdout.strip()[:800],
                stderr=val.stderr.strip()[:400],
            )
            logger.error(error.message, event=EngineeringEvent.BOOTSTRAP_FAILED.value, code=error.code)
            return {
                "ok": False,
                "tool": "reveng-bootstrap",
                "event": EngineeringEvent.BOOTSTRAP_FAILED.value,
                "errors": [error.to_dict()],
                "data": {"steps": steps},
            }
        steps.append({"step": "validate", "ok": True})

    logger.info("bootstrap completed", event=EngineeringEvent.BOOTSTRAP_COMPLETED.value)
    return {
        "ok": True,
        "tool": "reveng-bootstrap",
        "event": EngineeringEvent.BOOTSTRAP_COMPLETED.value,
        "errors": [],
        "data": {"steps": steps, "repo": str(repo), "transitional_desktop": cfg.get("transitional_desktop")},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reveng-bootstrap", description="Bootstrap RevENG engineering workspace")
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument("--skip-validate", action="store_true")
    parser.add_argument("--skip-pre-commit", action="store_true")
    args = parser.parse_args(argv)

    # Avoid recursive weirdness if REVENG_ENG vars unset
    os.environ.setdefault("REVENG_ENG_BOOTSTRAP", "1")

    repo = find_repo_root(args.repo) if args.repo is None else args.repo.resolve()
    summary = bootstrap(repo, skip_validate=args.skip_validate, skip_pre_commit=args.skip_pre_commit)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("Bootstrap OK" if summary["ok"] else "Bootstrap FAILED")
        for step in summary.get("data", {}).get("steps", []):
            print(f"  - {step.get('step')}: {'ok' if step.get('ok') else 'FAIL'}")

    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
