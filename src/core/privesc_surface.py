"""Privilege-escalation ATTACK SURFACE analysis — static, universal, defensive.

This is the honest version of the "kernel/root" capability. It does NOT build or
run exploits. It MAPS the attack surface a binary exposes — the concrete, located
weaknesses an attacker would pivot through to escalate: setuid/permission flaws,
hijackable library load paths, sandbox-weakening entitlements, and shell/identity
imports. Every finding is a verifiable fact about the file, with a severity and a
plain explanation of why it matters and how it would be abused.

Pure static analysis: works on any PE / ELF / Mach-O. Never executes the target.
"""

import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Imported functions that an escalation chain pivots through (exact-name match).
RISKY_IMPORTS = {
    "system": ("Executes a shell command", "high"),
    "popen": ("Opens a shell pipe", "high"),
    "execl": ("Replaces the process image", "medium"),
    "execlp": ("Shell-PATH exec — PATH-searched, hijackable", "high"),
    "execvp": ("Shell-PATH exec — PATH-searched, hijackable", "high"),
    "execve": ("Replaces the process image", "medium"),
    "setuid": ("Changes user identity (privilege transition)", "high"),
    "setgid": ("Changes group identity (privilege transition)", "high"),
    "seteuid": ("Changes effective user", "high"),
    "setresuid": ("Changes real/effective/saved uid", "high"),
    "dlopen": ("Loads a library at runtime (hijackable path)", "medium"),
    "LoadLibraryA": ("Loads a DLL at runtime (search-order hijack)", "medium"),
    "LoadLibraryW": ("Loads a DLL at runtime (search-order hijack)", "medium"),
    "WinExec": ("Executes a command", "high"),
    "ShellExecuteA": ("Executes a command via the shell", "high"),
}

# macOS entitlements that widen the attack surface (injection / weaker sandbox).
RISKY_ENTITLEMENTS = {
    "com.apple.security.cs.disable-library-validation":
        ("Allows loading unsigned libraries → code injection", "critical"),
    "com.apple.security.cs.allow-dyld-environment-variables":
        ("Honors DYLD_* env vars → dylib injection", "high"),
    "com.apple.security.cs.allow-unsigned-executable-memory":
        ("Allows unsigned executable memory → easier RCE", "high"),
    "com.apple.security.get-task-allow":
        ("Debuggable → another process can attach and inject", "high"),
    "com.apple.security.cs.allow-jit":
        ("Allows JIT (RWX) memory", "medium"),
    "com.apple.security.cs.disable-executable-page-protection":
        ("Disables W^X page protection", "critical"),
}


@dataclass
class Finding:
    severity: str
    category: str
    detail: str
    location: str = ""


def _permission_findings(path):
    out = []
    try:
        st = os.stat(path)
    except OSError:
        return out
    mode = st.st_mode
    if mode & stat.S_ISUID:
        owner = "root" if st.st_uid == 0 else f"uid {st.st_uid}"
        out.append(Finding(
            "critical", "setuid binary",
            f"setuid bit set, owned by {owner}: runs with the OWNER's privileges no "
            f"matter who launches it — the classic local privilege-escalation target. "
            f"A bug here (command injection, library hijack) yields the owner's rights.",
            path))
    if mode & stat.S_ISGID:
        out.append(Finding(
            "high", "setgid binary",
            f"setgid bit set (gid {st.st_gid}): runs with the group's privileges.", path))
    if mode & stat.S_IWOTH:
        out.append(Finding(
            "critical", "world-writable executable",
            "Any user can overwrite this binary — trivial code substitution; if it is "
            "ever run by a privileged user, that's instant escalation.", path))
    parent = os.path.dirname(os.path.abspath(path))
    try:
        pst = os.stat(parent)
        if (pst.st_mode & stat.S_IWOTH) and (mode & (stat.S_ISUID | stat.S_ISGID)):
            out.append(Finding(
                "high", "writable dir of privileged binary",
                f"Parent directory {parent} is world-writable while this binary is "
                f"setuid/setgid — enables file-swap and relative-path hijacks.", parent))
    except OSError:
        pass
    return out


def _macho_entitlements(path):
    """Read embedded entitlements via `codesign` (does NOT execute the binary)."""
    out = []
    if sys.platform != "darwin" or not shutil.which("codesign"):
        return out
    try:
        proc = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", path],
            capture_output=True, text=True, timeout=15)
        blob = proc.stdout + proc.stderr
    except Exception:
        return out
    for ent, (why, sev) in RISKY_ENTITLEMENTS.items():
        if ent in blob:
            out.append(Finding(sev, "risky entitlement", f"{ent} — {why}", path))
    return out


def _binary_findings(path):
    """Imports, library-load-path hijack surface, and signing/hardening via LIEF."""
    out = []
    try:
        import lief
        b = lief.parse(path)
    except Exception:
        return out
    if b is None:
        return out

    # Risky imported functions.
    names = set()
    try:
        for f in getattr(b, "imported_functions", []) or []:
            names.add(str(getattr(f, "name", f)))
    except Exception:
        pass
    try:
        for s in getattr(b, "symbols", []) or []:
            n = str(getattr(s, "name", "")).lstrip("_")
            if n:
                names.add(n)
    except Exception:
        pass
    for fn, (why, sev) in RISKY_IMPORTS.items():
        if fn in names or fn.lstrip("_") in names:
            out.append(Finding(sev, "dangerous import", f"{fn}() — {why}", path))

    # Mach-O dylib-hijack surface: @rpath-relative loads + LC_RPATH search paths.
    try:
        fmt = str(getattr(b, "format", "")).upper()
        if "MACHO" in fmt:
            rpaths, rpath_libs = [], []
            for cmd in getattr(b, "commands", []) or []:
                cname = type(cmd).__name__
                if cname == "RPathCommand" or "RPath" in cname:
                    rpaths.append(str(getattr(cmd, "path", "")))
            for lib in getattr(b, "libraries", []) or []:
                lname = str(getattr(lib, "name", lib))
                if lname.startswith("@rpath/"):
                    rpath_libs.append(lname)
            if rpath_libs and rpaths:
                out.append(Finding(
                    "medium", "dylib hijack surface",
                    f"Loads {len(rpath_libs)} @rpath-relative dylib(s) resolved through "
                    f"{len(rpaths)} LC_RPATH path(s) ({', '.join(rpaths[:3])}). If any "
                    f"search path is user-writable, a planted dylib is loaded with this "
                    f"process's privileges.", path))
    except Exception:
        pass

    # Code signature presence.
    try:
        has_sig = bool(getattr(b, "has_code_signature", False))
        if "MACHO" in str(getattr(b, "format", "")).upper() and not has_sig:
            out.append(Finding(
                "medium", "unsigned binary",
                "No embedded code signature — the binary can be modified or replaced "
                "without breaking a signature check.", path))
    except Exception:
        pass

    return out


def analyze(path):
    """Return sorted Findings describing the privesc attack surface of one file."""
    findings = []
    findings += _permission_findings(path)
    findings += _macho_entitlements(path)
    findings += _binary_findings(path)
    findings.sort(key=lambda f: _SEV_RANK.get(f.severity, 9))
    return findings


def format_report(findings, path=""):
    if not findings:
        return (f"Privilege-escalation surface for {path or 'target'}: none detected.\n"
                "No setuid/permission flaws, risky entitlements, hijackable load paths, "
                "or shell/identity imports found by static analysis.")
    lines = [f"PRIVILEGE-ESCALATION ATTACK SURFACE — {path or findings[0].location}",
             f"{len(findings)} finding(s), highest severity: {findings[0].severity.upper()}",
             ""]
    for f in findings:
        lines.append(f"  [{f.severity.upper()}] {f.category}")
        lines.append(f"      {f.detail}")
        if f.location:
            lines.append(f"      at: {f.location}")
    lines.append("")
    lines.append("Note: this is a STATIC surface map — concrete weaknesses, not a working "
                 "exploit. It shows where an escalation chain would attack, for hardening "
                 "or authorized assessment.")
    return "\n".join(lines)
