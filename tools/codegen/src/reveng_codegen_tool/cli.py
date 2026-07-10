"""reveng-codegen — engineering codegen scaffolding CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from reveng_codegen import (
    GENERATOR_NAME,
    has_proto_sources,
    list_proto_files,
    output_dir,
    proto_dir,
)
from reveng_config import find_repo_root
from reveng_errors import err
from reveng_logging import get_logger
from reveng_types import EngineeringEvent

logger = get_logger("reveng-codegen")


def _git_status_porcelain(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout


def _write_generated_scaffold(repo: Path, proto_files: list[Path]) -> Path:
    out = output_dir(repo)
    out.mkdir(parents=True, exist_ok=True)
    init = out / "__init__.py"
    digest = hashlib.sha256()
    for path in proto_files:
        digest.update(path.read_bytes())
        digest.update(b"\0")
    content = (
        '"""Generated stub package. Do not hand-edit."""\n\n'
        f'__generated_by__ = "{GENERATOR_NAME}"\n'
        f'__proto_digest__ = "{digest.hexdigest()}"\n'
        f"__proto_count__ = {len(proto_files)}\n"
    )
    init.write_text(content, encoding="utf-8")

    # Emit one marker module per proto stem (engineering scaffold only; no protobuf runtime)
    for path in proto_files:
        rel = path.relative_to(proto_dir(repo))
        module_name = "_".join(rel.with_suffix("").parts).replace("-", "_")
        target = out / f"{module_name}.py"
        target.write_text(
            f'"""Generated marker for {rel.as_posix()}. Do not hand-edit."""\n\n'
            f'__generated_by__ = "{GENERATOR_NAME}"\n'
            f'__source_proto__ = "{rel.as_posix()}"\n',
            encoding="utf-8",
        )
    return out


def run_codegen(repo: Path, *, verify_dirty: bool = False) -> dict[str, Any]:
    protos = list_proto_files(repo)
    if not protos:
        logger.info(
            "no proto sources; codegen scaffold idle",
            event=EngineeringEvent.CODEGEN_COMPLETED.value,
            proto_dir=str(proto_dir(repo)),
        )
        # Ensure generated package exists as empty scaffold
        out = output_dir(repo)
        out.mkdir(parents=True, exist_ok=True)
        init = out / "__init__.py"
        if not init.is_file():
            init.write_text(
                f'"""Generated stub package. Do not hand-edit."""\n\n__generated_by__ = "{GENERATOR_NAME}"\n',
                encoding="utf-8",
            )
        return {
            "ok": True,
            "tool": "reveng-codegen",
            "event": EngineeringEvent.CODEGEN_COMPLETED.value,
            "errors": [],
            "data": {
                "proto_present": False,
                "proto_count": 0,
                "output_dir": str(out),
                "verify_dirty": verify_dirty,
            },
        }

    before = _git_status_porcelain(repo) if verify_dirty else ""
    out = _write_generated_scaffold(repo, protos)
    after = _git_status_porcelain(repo) if verify_dirty else ""

    if verify_dirty and after != before:
        # If only generated files changed relative to index expectation, still fail verify-dirty
        # when working tree is dirty after generation (CI mode).
        drift = err(
            "ENG.CODEGEN.DRIFT",
            "working tree dirty after codegen (verify-dirty)",
            before=before,
            after=after,
        )
        logger.error(
            drift.message,
            event=EngineeringEvent.CODEGEN_DRIFT_DETECTED.value,
            code=drift.code,
        )
        return {
            "ok": False,
            "tool": "reveng-codegen",
            "event": EngineeringEvent.CODEGEN_DRIFT_DETECTED.value,
            "errors": [drift.to_dict()],
            "data": {"proto_count": len(protos), "output_dir": str(out)},
        }

    logger.info(
        "codegen completed",
        event=EngineeringEvent.CODEGEN_COMPLETED.value,
        proto_count=len(protos),
    )
    return {
        "ok": True,
        "tool": "reveng-codegen",
        "event": EngineeringEvent.CODEGEN_COMPLETED.value,
        "errors": [],
        "data": {
            "proto_present": True,
            "proto_count": len(protos),
            "protos": [str(p.relative_to(repo)) for p in protos],
            "output_dir": str(out),
            "verify_dirty": verify_dirty,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reveng-codegen", description="Engineering codegen scaffolding")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--repo", type=Path, default=None)
    parser.add_argument(
        "--verify-dirty",
        action="store_true",
        help="Fail if working tree is dirty after codegen",
    )
    args = parser.parse_args(argv)

    repo = find_repo_root(args.repo) if args.repo is None else args.repo.resolve()
    # Detect missing proto directory explicitly
    if not proto_dir(repo).exists():
        error = err("ENG.CODEGEN.PROTO_DIR_MISSING", "proto/ directory missing", path=str(proto_dir(repo)))
        summary = {
            "ok": False,
            "tool": "reveng-codegen",
            "event": EngineeringEvent.CODEGEN_DRIFT_DETECTED.value,
            "errors": [error.to_dict()],
            "data": {},
        }
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print("Codegen FAILED: proto/ missing")
        return 1

    # has_proto_sources used for logging clarity
    _ = has_proto_sources(repo)
    summary = run_codegen(repo, verify_dirty=args.verify_dirty)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("Codegen OK" if summary["ok"] else "Codegen FAILED")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
