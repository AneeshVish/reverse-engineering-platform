"""Whole-application ("bundle") analysis.

An application is usually a folder/bundle of many files, not a single binary.
This module walks such a tree, classifies every file, produces a deep per-binary
summary using the engines we already have (no external tools required), and
aggregates a report over the whole app.
"""

import hashlib
import math
import os
import re
from collections import Counter

from src.core.universal_loader import UniversalLoader, FileType

# Quick indicators of embedded secrets (best-effort, byte-level).
_SECRET_RE = re.compile(
    rb"(api[_-]?key|secret|passwd|password|private[_-]?key|"
    rb"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.)",
    re.IGNORECASE,
)
_BINARY_TYPES = {FileType.PE, FileType.ELF, FileType.MACHO}
_SOURCE_EXTS = (".py", ".js", ".ts", ".java", ".c", ".cc", ".cpp", ".h", ".cs", ".go", ".rb")
_MAX_SCAN = 8 * 1024 * 1024  # cap per-file byte scan at 8 MB


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classify_path(path):
    """Cheap classification by extension/role (no parsing)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in _SOURCE_EXTS:
        return "source"
    if ext in (".dll", ".so", ".dylib"):
        return "library"
    if ext in (".exe", ".bin"):
        return "executable"
    return "other"


def analyze_binary_file(path):
    """Deep, tool-free summary for one file. Always returns a dict (never raises)."""
    summary = {"path": path, "kind": classify_path(path)}
    try:
        summary["size"] = os.path.getsize(path)
    except OSError:
        summary["size"] = 0
        return summary

    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_SCAN)
    except OSError as e:
        summary["error"] = str(e)
        return summary

    summary["sha256"] = hashlib.sha256(data).hexdigest()
    summary["entropy"] = round(shannon_entropy(data[:65536]), 3)
    summary["secret_hits"] = len(_SECRET_RE.findall(data))

    loader = UniversalLoader()
    try:
        loader.load(path)
        ft = getattr(loader, "file_type", None)
        summary["type"] = ft.name if isinstance(ft, FileType) else str(ft)
        summary["is_binary"] = ft in _BINARY_TYPES
        parsed = getattr(loader, "parsed", None)
        if parsed is not None:
            try:
                summary["sections"] = len(list(getattr(parsed, "sections", []) or []))
            except Exception:
                summary["sections"] = 0
            try:
                summary["functions"] = len(list(getattr(parsed, "functions", []) or []))
            except Exception:
                summary["functions"] = 0
    except Exception as e:
        summary["error"] = str(e)
        summary["is_binary"] = False

    # Packing heuristic: UPX section name or very high entropy.
    summary["packed"] = (summary.get("entropy", 0) > 7.2) or (
        "upx" in summary.get("type", "").lower())
    return summary


def render_summary(summary):
    """Human-readable text block for one file's summary."""
    lines = [f"File: {summary.get('path', '')}", f"  Kind: {summary.get('kind', '?')}"]
    if "type" in summary:
        lines.append(f"  Format: {summary['type']}")
    lines.append(f"  Size: {summary.get('size', 0):,} bytes")
    if "sha256" in summary:
        lines.append(f"  SHA-256: {summary['sha256']}")
    if summary.get("is_binary"):
        lines.append(f"  Sections: {summary.get('sections', 0)} | "
                     f"Functions: {summary.get('functions', 0)}")
    if "entropy" in summary:
        flag = "  ⚠ likely packed/encrypted" if summary.get("packed") else ""
        lines.append(f"  Entropy: {summary['entropy']}{flag}")
    if summary.get("secret_hits"):
        lines.append(f"  Possible embedded secrets: {summary['secret_hits']} hit(s)")
    if "error" in summary:
        lines.append(f"  Note: {summary['error']}")
    return "\n".join(lines)


def summarize_bundle(results):
    """Aggregate a top-level report over a {rel_path: summary} mapping."""
    files = [v for v in results.values() if isinstance(v, dict)]
    binaries = [f for f in files if f.get("is_binary")]
    total_functions = sum(f.get("functions", 0) for f in binaries)
    total_secrets = sum(f.get("secret_hits", 0) for f in files)
    packed = [f for f in binaries if f.get("packed")]
    by_type = Counter(f.get("type", "?") for f in binaries)

    lines = [
        "===== APPLICATION ANALYSIS SUMMARY =====",
        f"Total files analyzed: {len(files)}",
        f"Binaries: {len(binaries)}  ({dict(by_type)})",
        f"Total functions discovered: {total_functions}",
        f"Files with possible secrets: {sum(1 for f in files if f.get('secret_hits'))} "
        f"({total_secrets} hits)",
        f"Likely packed/encrypted binaries: {len(packed)}",
    ]
    if packed:
        lines.append("  Packed: " + ", ".join(os.path.basename(f["path"]) for f in packed[:10]))
    return "\n".join(lines)
