"""Run helper scripts from the GUI in both dev and PyInstaller builds."""

from __future__ import annotations

import io
import runpy
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout

from src.utils.paths import is_frozen, script_path


def run_script(name: str, args: list[str] | None = None, **kwargs) -> subprocess.CompletedProcess:
    """Execute scripts/<name>.py and return stdout/stderr like subprocess.run."""
    args = list(args or [])
    path = script_path(name)

    if not is_frozen():
        cmd = [sys.executable, path, *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
        )

    old_argv = sys.argv
    out = io.StringIO()
    err = io.StringIO()
    code = 0
    sys.argv = [path, *args]
    try:
        with redirect_stdout(out), redirect_stderr(err):
            runpy.run_path(path, run_name="__main__")
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:
        err.write(str(exc))
        code = 1
    finally:
        sys.argv = old_argv

    return subprocess.CompletedProcess(
        args=[path, *args],
        returncode=code,
        stdout=out.getvalue(),
        stderr=err.getvalue(),
    )
