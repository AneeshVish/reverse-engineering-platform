"""Process and file instrumentation — child processes, local SQLite."""

import os
import re
import sqlite3
import subprocess
from typing import Dict, List, Any, Optional


def list_child_processes(pid: int) -> List[Dict]:
    """List child PIDs (macOS/Linux ps)."""
    if not pid:
        return []
    try:
        out = subprocess.check_output(
            ["ps", "-o", "pid,ppid,comm", "-p", str(pid)],
            stderr=subprocess.DEVNULL, text=True, timeout=5)
        lines = out.strip().splitlines()[1:]
        return [{"pid": int(l.split()[0]), "comm": l.split()[-1]} for l in lines if l.strip()]
    except Exception:
        return []


def find_sqlite_files(root: str, max_files: int = 20) -> List[str]:
    """Find .sqlite/.db files under root."""
    found = []
    if not root or not os.path.isdir(root):
        return found
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith((".sqlite", ".sqlite3", ".db")):
                found.append(os.path.join(dirpath, fn))
                if len(found) >= max_files:
                    return found
    return found


def peek_sqlite(path: str) -> Dict:
    """List tables in a SQLite file (read-only)."""
    result = {"path": path, "tables": [], "error": ""}
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 20")
        result["tables"] = [r[0] for r in cur.fetchall()]
        conn.close()
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_electron_userdata(app_name: str = "") -> Dict:
    """Scan common Electron userData locations on macOS."""
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Library", "Application Support", app_name) if app_name else "",
        os.path.join(home, "Library", "Application Support"),
    ]
    result = {"sqlite_files": [], "table_info": []}
    for base in candidates:
        if not base or not os.path.isdir(base):
            continue
        for sf in find_sqlite_files(base, 10):
            result["sqlite_files"].append(sf)
            result["table_info"].append(peek_sqlite(sf))
    return result


def format_report(scan: Dict) -> str:
    lines = ["PROCESS / FILE MONITOR", "=" * 60]
    if scan.get("sqlite_files"):
        lines.append(f"Local SQLite files: {len(scan['sqlite_files'])}")
        for info in scan.get("table_info", [])[:5]:
            lines.append(f"  {info.get('path', '?')}: tables={info.get('tables', [])}")
    else:
        lines.append("No local SQLite databases found in scanned paths.")
    return "\n".join(lines)
