"""Filesystem path helpers — work from source tree or a PyInstaller bundle."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def _dev_project_root() -> Path:
    # src/utils/paths.py -> project root is two directories up.
    return Path(__file__).resolve().parent.parent.parent


def bundle_root() -> Path:
    """Read-only bundled resources (assets, scripts, default config)."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return _dev_project_root()


def project_root() -> str:
    """Legacy alias — bundled resource root in frozen builds."""
    return str(bundle_root())


def user_data_dir() -> Path:
    """Writable per-user directory (config, projects, plugins, temp)."""
    override = os.environ.get("REVENG_DATA_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "RevENG"
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home())) / "RevENG"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "RevENG"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _ensure_user_layout() -> None:
    """Seed user data from the bundle on first launch."""
    if not is_frozen():
        return
    root = user_data_dir()
    for name in ("plugins", "projects", "temp", "scripts"):
        (root / name).mkdir(parents=True, exist_ok=True)

    cfg = root / "config.json"
    bundled_cfg = bundle_root() / "config.json"
    if not cfg.exists() and bundled_cfg.is_file():
        shutil.copy2(bundled_cfg, cfg)

    bundled_plugins = bundle_root() / "plugins"
    if bundled_plugins.is_dir():
        for src in bundled_plugins.glob("*.py"):
            dest = root / "plugins" / src.name
            if not dest.exists():
                shutil.copy2(src, dest)


def asset_path(*parts: str) -> str:
    return str(bundle_root().joinpath("assets", *parts))


def script_path(name: str) -> str:
    """Absolute path to scripts/<name> (adds .py if missing)."""
    if not name.endswith(".py"):
        name += ".py"
    bundled = bundle_root() / "scripts" / name
    if is_frozen():
        dest = user_data_dir() / "scripts" / name
        if not dest.exists() and bundled.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundled, dest)
        return str(dest)
    return str(bundled)


# Backward-compatible module-level constant (dev tree root).
PROJECT_ROOT = str(_dev_project_root())
