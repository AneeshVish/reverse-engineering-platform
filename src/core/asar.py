"""Reader/extractor for Electron `.asar` archives.

Electron apps (Discord, Slack, VS Code, Notion, ...) ship their *actual source*
as JavaScript packed in `app.asar`. Unlike native binaries, this is not lost to
compilation — extracting the asar recovers the real source files. This is a small,
dependency-free parser of the asar (Chromium Pickle header + concatenated data).
"""

import json
import os
import struct


def is_asar(path):
    """True if `path` looks like an Electron asar archive."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return False
    if len(head) < 16:
        return False
    try:
        s0, _hdr, _objsz, json_len = struct.unpack("<4I", head)
    except struct.error:
        return False
    # First field is the pickle size marker (4); the JSON header has a sane length.
    return s0 == 4 and 0 < json_len <= 256 * 1024 * 1024


def _read_header(f):
    head = f.read(16)
    _s0, hdr_size, _objsz, json_len = struct.unpack("<4I", head)
    header_json = f.read(json_len).decode("utf-8", "replace")
    files = json.loads(header_json).get("files", {})
    data_base = 8 + hdr_size   # file data begins right after the pickle header
    return files, data_base


def list_asar(path):
    """Return a flat list of (relative_path, size) entries without extracting."""
    entries = []

    def walk(node, rel):
        for name, meta in node.items():
            r = os.path.join(rel, name) if rel else name
            if isinstance(meta, dict) and "files" in meta:
                walk(meta["files"], r)
            elif isinstance(meta, dict) and "size" in meta:
                entries.append((r, int(meta.get("size", 0))))

    with open(path, "rb") as f:
        files, _base = _read_header(f)
    walk(files, "")
    return entries


def extract_asar(path, dest):
    """Extract every file from an asar into `dest`. Returns the count written.

    Guards against path traversal (asar members are trusted-ish, but we analyze
    arbitrary apps). Returns 0 if the file isn't a valid asar.
    """
    if not is_asar(path):
        return 0
    dest_abs = os.path.abspath(dest)
    count = 0

    def within(target):
        return os.path.abspath(target).startswith(dest_abs + os.sep)

    def walk(f, node, base, rel):
        nonlocal count
        for name, meta in node.items():
            target = os.path.join(dest, rel, name)
            if not within(target):
                continue
            if isinstance(meta, dict) and "files" in meta:
                os.makedirs(target, exist_ok=True)
                walk(f, meta["files"], base, os.path.join(rel, name))
            elif isinstance(meta, dict) and "offset" in meta and "size" in meta:
                try:
                    off = base + int(meta["offset"])
                    size = int(meta["size"])
                    f.seek(off)
                    data = f.read(size)
                    os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
                    with open(target, "wb") as out:
                        out.write(data)
                    count += 1
                except (OSError, ValueError):
                    continue
            # entries with neither (e.g. 'unpacked') live in app.asar.unpacked/.

    try:
        with open(path, "rb") as f:
            files, base = _read_header(f)
            walk(f, files, base, "")
    except (OSError, ValueError, KeyError, struct.error):
        return count
    return count
