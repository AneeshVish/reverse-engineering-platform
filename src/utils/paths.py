"""Filesystem path helpers so the app works regardless of the current directory.

Panels used to invoke scripts via the relative path "scripts/foo.py", which only
worked when the process was started from the project root. These helpers resolve
locations against the project root (two levels up from this file: src/utils/).
"""

import os

# src/utils/paths.py -> project root is two directories up.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def project_root():
    return PROJECT_ROOT


def script_path(name):
    """Absolute path to scripts/<name> (adds .py if missing)."""
    if not name.endswith(".py"):
        name += ".py"
    return os.path.join(PROJECT_ROOT, "scripts", name)
