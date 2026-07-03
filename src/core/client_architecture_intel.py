"""Extract architecture intelligence from a target path (app, folder, binary)."""

import json
import os
import re
from typing import Dict, List, Any

from src.core import architecture_lexicon as lex
from src.core import traffic_capture as tc

_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9._\-/:?&=%+#]+|"
    r"(?:api|staging|internal|debug)[.][a-zA-Z0-9._\-]+|"
    r"/(?:api|v[0-9]+|admin|debug|internal|health|status)[/\w.-]*",
    re.I,
)
_FLAG_RE = re.compile(
    r"(?:feature[_-]?flag|enable[A-Z]\w+|DEBUG_\w+|__DEV__|process\.env\.(\w+))",
    re.I,
)
_GRPC_RE = re.compile(r"(?:rpc|service)\s+(\w+)\s*\{|\.proto\b|grpc\.(?:web\.)?enable", re.I)


def analyze_path(root_path: str, max_files: int = 500) -> Dict[str, Any]:
    """Walk root_path and extract architecture intel."""
    result = {
        "path": root_path,
        "hits": [],
        "endpoints": [],
        "hosts": set(),
        "feature_flags": [],
        "grpc_services": [],
        "dependencies": [],
        "files_scanned": 0,
    }
    if not root_path or not os.path.exists(root_path):
        return _finalize(result)

    scan_exts = {".js", ".ts", ".json", ".env", ".yaml", ".yml", ".plist",
                 ".xml", ".html", ".py", ".go", ".rs", ".java", ".cs", ".proto",
                 ".txt", ".md", ".cfg", ".conf", ".ini", ""}

    if os.path.isfile(root_path):
        _scan_file(root_path, result)
    else:
        count = 0
        for dirpath, _, filenames in os.walk(root_path):
            if count >= max_files:
                break
            # Skip huge framework dirs
            skip = {"node_modules", ".git", "__pycache__", "Frameworks"}
            if any(s in dirpath for s in skip):
                continue
            for fn in filenames:
                if count >= max_files:
                    break
                ext = os.path.splitext(fn)[1].lower()
                if ext not in scan_exts and ext not in (".dylib", ".so", ".dll", ".exe"):
                    continue
                fpath = os.path.join(dirpath, fn)
                _scan_file(fpath, result)
                count += 1

    # package.json dependencies
    pkg = os.path.join(root_path, "package.json") if os.path.isdir(root_path) else ""
    if pkg and os.path.isfile(pkg):
        try:
            with open(pkg, "r", encoding="utf-8") as f:
                data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name in deps:
                result["dependencies"].append(name)
                for h in lex.scan_text(name, "package.json"):
                    result["hits"].append(h)
        except Exception:
            pass

    return _finalize(result)


def _scan_file(fpath: str, result: Dict):
    result["files_scanned"] += 1
    rel = fpath
    try:
        size = os.path.getsize(fpath)
        if size > 8 * 1024 * 1024:
            return
        with open(fpath, "rb") as f:
            data = f.read()
    except OSError:
        return

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    for h in lex.scan_bytes(data, rel):
        result["hits"].append(h)

    for m in _URL_RE.finditer(text):
        val = m.group(0)
        if val.startswith("http"):
            from src.core.endpoint_correlation import host_of
            h = host_of(val)
            if h:
                result["hosts"].add(h)
        if val not in result["endpoints"]:
            result["endpoints"].append(val)

    for m in _FLAG_RE.finditer(text):
        flag = m.group(0)
        if flag not in [f["name"] for f in result["feature_flags"]]:
            result["feature_flags"].append({"name": flag, "file": rel})

    for m in _GRPC_RE.finditer(text):
        svc = m.group(1) if m.lastindex else m.group(0)
        if svc and svc not in result["grpc_services"]:
            result["grpc_services"].append(svc)


def _finalize(result: Dict) -> Dict:
    result["hosts"] = sorted(result["hosts"])
    # Dedupe hits
    seen = set()
    unique = []
    for h in result["hits"]:
        k = (h["category"], h["keyword"], h["source"])
        if k not in seen:
            seen.add(k)
            unique.append(h)
    result["hits"] = unique
    return result


def format_report(intel: Dict[str, Any]) -> str:
    if not intel or not intel.get("hits") and not intel.get("endpoints"):
        return ("No architecture intelligence extracted yet.\n"
                "Open an app bundle or folder in Full Software to scan.")
    lines = ["CLIENT ARCHITECTURE INTELLIGENCE", "=" * 60]
    lines.append(f"Path: {intel.get('path', '?')}")
    lines.append(f"Files scanned: {intel.get('files_scanned', 0)}")
    cats = lex.categories_found(intel.get("hits", []))
    if cats:
        lines.append(f"\nCategories detected: {', '.join(cats)}")
    if intel.get("dependencies"):
        lines.append(f"\nDependencies ({len(intel['dependencies'])}): " +
                     ", ".join(intel["dependencies"][:20]))
    if intel.get("feature_flags"):
        lines.append(f"\nFeature flags ({len(intel['feature_flags'])}):")
        for f in intel["feature_flags"][:15]:
            lines.append(f"  • {f['name']}  ({f['file']})")
    if intel.get("grpc_services"):
        lines.append(f"\ngRPC services: {', '.join(intel['grpc_services'][:10])}")
    if intel.get("endpoints"):
        lines.append(f"\nEmbedded endpoints ({len(intel['endpoints'])}):")
        for ep in intel["endpoints"][:30]:
            lines.append(f"  • {ep}")
    if intel.get("hosts"):
        lines.append(f"\nHosts: {', '.join(intel['hosts'][:20])}")
    lines.append(f"\nKeyword hits ({len(intel.get('hits', []))}):")
    for h in intel.get("hits", [])[:40]:
        lines.append(f"  [{h['category']}] {h['keyword']}  @ {h['source']}")
    lines.append("\nNote: strings in the binary do NOT prove production use — "
                 "correlate with live capture for confirmation.")
    return "\n".join(lines)


def to_evidence(intel: Dict[str, Any]):
    """Push EXTRACTED evidence items into session store."""
    from src.core.evidence_store import session_store, L1, EXTRACTED, CONF_WEAK, EvidenceItem, EvidenceArtifact
    store = session_store()
    for h in intel.get("hits", [])[:100]:
        store.add(EvidenceItem(
            claim=f"Binary/source references '{h['keyword']}' ({h['category']})",
            level=L1, kind=EXTRACTED, category=h.get("category", "binary"),
            confidence=CONF_WEAK,
            artifacts=[EvidenceArtifact(h.get("context", h["keyword"]), h["source"])],
            confounders=["Presence in source does not prove production use."],
            source_tab="Full Software", source_module="client_architecture_intel",
        ))
    for ep in intel.get("endpoints", [])[:50]:
        store.add(EvidenceItem(
            claim=f"Embedded endpoint/path found: {ep}",
            level=L1, kind=EXTRACTED, category="binary",
            confidence=CONF_WEAK,
            artifacts=[EvidenceArtifact(ep, intel.get("path", ""))],
            confounders=["May be dead code or documentation string."],
            source_tab="Full Software", source_module="client_architecture_intel",
        ))
