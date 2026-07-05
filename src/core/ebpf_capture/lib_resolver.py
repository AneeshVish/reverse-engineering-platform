"""Resolve libssl.so path for eBPF uprobe attachment."""

import glob
import os
import sys

_CANDIDATES = [
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib64/libssl.so.3",
    "/usr/lib64/libssl.so.1.1",
]


def resolve_ssl_library() -> str:
    for path in _CANDIDATES:
        if os.path.isfile(path):
            return path
    for pattern in ("/lib/*/libssl.so.3", "/usr/lib/*/libssl.so.3"):
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return _CANDIDATES[0] if sys.platform == "linux" else ""
