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
import tarfile
import tempfile
import zipfile
from collections import Counter

from src.core.universal_loader import UniversalLoader, FileType

# Archive containers that hold an application's many files. APK/IPA/JAR/WAR/WHL
# and Electron .asar are all really zip/zip-like; installers vary.
_ARCHIVE_EXTS = (".zip", ".jar", ".apk", ".ipa", ".war", ".whl", ".egg", ".aar",
                 ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".nupkg")

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

    # Full protection report for actual binaries (lazy import avoids a cycle).
    if summary.get("is_binary"):
        try:
            from src.core import protection_detector
            rep = protection_detector.detect_protections(path)
            summary["protection_level"] = rep["level"]
            summary["protections"] = [p["name"] for p in rep["protections"]]
            if rep["level"] in ("heavy", "medium", "light"):
                summary["packed"] = True
        except Exception:
            pass
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


def resolve_app_executable(app_path):
    """For a macOS .app bundle (a directory), return its main executable path.

    Reads Contents/Info.plist (CFBundleExecutable); falls back to the first file
    in Contents/MacOS/. Returns None if it isn't a resolvable .app.
    """
    macos_dir = os.path.join(app_path, "Contents", "MacOS")
    if not os.path.isdir(macos_dir):
        return None
    name = None
    try:
        import plistlib
        with open(os.path.join(app_path, "Contents", "Info.plist"), "rb") as f:
            name = plistlib.load(f).get("CFBundleExecutable")
    except Exception:
        name = None
    if name:
        exe = os.path.join(macos_dir, name)
        if os.path.isfile(exe):
            return exe
    try:
        for f in sorted(os.listdir(macos_dir)):
            full = os.path.join(macos_dir, f)
            if os.path.isfile(full):
                return full
    except OSError:
        pass
    return None


def is_archive(path):
    low = path.lower()
    if low.endswith(_ARCHIVE_EXTS) or low.endswith(".asar"):
        return True
    try:
        if zipfile.is_zipfile(path) or tarfile.is_tarfile(path):
            return True
    except OSError:
        return False
    try:
        from src.core.asar import is_asar
        return is_asar(path)
    except Exception:
        return False


def _safe_extract(path, dest):
    """Extract a zip/tar to dest, guarding against path-traversal (zip-slip).

    We analyze hostile input, so any member that resolves outside dest is skipped.
    Returns True if anything was extracted.
    """
    dest = os.path.abspath(dest)

    def _within(target):
        return os.path.abspath(target).startswith(dest + os.sep)

    try:
        # Electron asar archives (real JS source).
        try:
            from src.core.asar import is_asar, extract_asar
            if is_asar(path):
                return extract_asar(path, dest) > 0
        except Exception:
            pass
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                for member in z.namelist():
                    target = os.path.join(dest, member)
                    if _within(target):
                        z.extract(member, dest)
            return True
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                for member in t.getmembers():
                    target = os.path.join(dest, member.name)
                    if member.isfile() and _within(target):
                        t.extract(member, dest)
            return True
    except Exception:
        return False
    return False


def analyze_application(root, max_depth=2, _depth=0, _prefix=""):
    """Analyze a whole application: a folder, or an archive (apk/jar/ipa/zip/...).

    Recurses into nested archives up to max_depth so a real app bundle is fully
    walked. Returns {display_path: summary}. Never raises on a bad member.
    """
    results = {}

    # A single archive at the top: extract and recurse.
    if os.path.isfile(root) and is_archive(root) and _depth < max_depth:
        tmp = tempfile.mkdtemp(prefix="reapp_")
        if _safe_extract(root, tmp):
            inner = analyze_application(tmp, max_depth, _depth + 1,
                                        _prefix=_prefix + os.path.basename(root) + "!/")
            results.update(inner)
            return results
        # Not extractable: analyze as a plain file.
        results[_prefix + os.path.basename(root)] = analyze_binary_file(root)
        return results

    if os.path.isfile(root):
        results[_prefix + os.path.basename(root)] = analyze_binary_file(root)
        return results

    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            fpath = os.path.join(dirpath, name)
            rel = _prefix + os.path.relpath(fpath, root)
            if is_archive(fpath) and _depth < max_depth:
                tmp = tempfile.mkdtemp(prefix="reapp_")
                if _safe_extract(fpath, tmp):
                    results.update(analyze_application(
                        tmp, max_depth, _depth + 1, _prefix=rel + "!/"))
                    continue
            results[rel] = analyze_binary_file(fpath)
    return results


def summarize_bundle(results):
    """Aggregate a top-level report over a {rel_path: summary} mapping."""
    files = [v for v in results.values() if isinstance(v, dict)]
    binaries = [f for f in files if f.get("is_binary")]
    total_functions = sum(f.get("functions", 0) for f in binaries)
    total_secrets = sum(f.get("secret_hits", 0) for f in files)
    packed = [f for f in binaries if f.get("packed")]
    protected = [f for f in binaries if f.get("protection_level") == "heavy"]
    by_type = Counter(f.get("type", "?") for f in binaries)
    protector_names = sorted({p for f in binaries for p in f.get("protections", [])})

    lines = [
        "===== APPLICATION ANALYSIS SUMMARY =====",
        f"Total files analyzed: {len(files)}",
        f"Binaries: {len(binaries)}  ({dict(by_type)})",
        f"Total functions discovered: {total_functions}",
        f"Files with possible secrets: {sum(1 for f in files if f.get('secret_hits'))} "
        f"({total_secrets} hits)",
        f"Likely packed/encrypted binaries: {len(packed)}",
    ]
    if protector_names:
        lines.append(f"Protections detected: {', '.join(protector_names)}")
    if protected:
        lines.append("  Heavy protectors (manual work required): "
                     + ", ".join(os.path.basename(f["path"]) for f in protected[:10]))
    if packed:
        lines.append("  Packed: " + ", ".join(os.path.basename(f["path"]) for f in packed[:10]))
    return "\n".join(lines)
