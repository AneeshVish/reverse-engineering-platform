"""Electron application support.

Electron apps (Discord, Slack, VS Code, Notion, Spotify, ...) are JavaScript apps
wrapped in a native launcher. The native executable you can `Open` is a thin stub;
the *real* source is JavaScript inside `Contents/Resources/app.asar`. This module
detects such apps and extracts that real source.
"""

import os

from src.core.asar import extract_asar, is_asar


def find_enclosing_app(path):
    """Walk up from a file/dir to the containing macOS .app bundle, if any."""
    p = os.path.abspath(path)
    while p and p != os.path.dirname(p):
        if p.endswith(".app") and os.path.isdir(p):
            return p
        p = os.path.dirname(p)
    return None


def asar_paths(app):
    """Return existing app.asar paths inside a .app bundle."""
    out = []
    res = os.path.join(app, "Contents", "Resources")
    for name in ("app.asar", "default_app.asar"):
        f = os.path.join(res, name)
        if os.path.isfile(f) and is_asar(f):
            out.append(f)
    return out


def is_electron_app(app):
    """True if the .app bundle is an Electron app."""
    if not app or not os.path.isdir(app):
        return False
    if asar_paths(app):
        return True
    fw = os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework")
    return os.path.isdir(fw)


def extract_source(app, dest):
    """Extract the real JS source (all app.asar) into `dest`. Returns file count."""
    total = 0
    for a in asar_paths(app):
        total += extract_asar(a, dest)
    # asar.unpacked dirs hold native modules shipped alongside; copy their tree too.
    for a in asar_paths(app):
        unpacked = a + ".unpacked"
        if os.path.isdir(unpacked):
            for root, _dirs, files in os.walk(unpacked):
                for fn in files:
                    total += 1  # counted; left in place (not copied) to stay cheap
    return total
