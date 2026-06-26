"""Packer / protector / anti-analysis detection, with an honest verdict on what
can be unpacked automatically vs. what needs manual reverse engineering.

This is the realistic version of "defeat obfuscation/packing/DRM": we reliably
*identify* the protection and automatically unpack the cases that are genuinely
automatable (UPX). For heavy commercial protectors (VMProtect, Themida, ...) we
say so plainly rather than pretending to break them.
"""

import os
import shutil
import subprocess

from src.core.universal_loader import UniversalLoader
from src.core.bundle_analysis import shannon_entropy

# Section-name -> (protector name, automatable). Section names are the most
# reliable indicator for PE packers/protectors.
SECTION_SIGNATURES = {
    "upx0": ("UPX", True), "upx1": ("UPX", True), "upx2": ("UPX", True),
    ".aspack": ("ASPack", False), ".adata": ("ASPack", False),
    ".vmp0": ("VMProtect", False), ".vmp1": ("VMProtect", False), ".vmp2": ("VMProtect", False),
    ".themida": ("Themida", False), ".winlice": ("WinLicense/Themida", False),
    ".enigma1": ("Enigma Protector", False), ".enigma2": ("Enigma Protector", False),
    ".mpress1": ("MPRESS", False), ".mpress2": ("MPRESS", False),
    "pec1": ("PECompact", False), "pec2": ("PECompact", False),
    ".petite": ("Petite", False),
    ".aspr": ("ASProtect", False),
    ".nsp0": ("NsPack", False), ".nsp1": ("NsPack", False),
    ".obsidium": ("Obsidium", False),
    ".y0da": ("yoda's crypter", False),
}

# Raw byte signatures (searched in the first part of the file) as a fallback.
BYTE_SIGNATURES = [
    (b"UPX!", ("UPX", True)),
    (b"VMProtect", ("VMProtect", False)),
    (b"Themida", ("Themida", False)),
    (b".enigma", ("Enigma Protector", False)),
]

HEAVY = {"VMProtect", "Themida", "WinLicense/Themida", "Enigma Protector",
         "ASProtect", "Obsidium"}


def detect_protections(path):
    """Return a structured protection report (never raises)."""
    report = {
        "path": path, "protections": [], "overall_entropy": 0.0,
        "high_entropy": False, "level": "none", "automatable": False,
        "guidance": "", "unpacked_path": None,
    }
    try:
        with open(path, "rb") as f:
            head = f.read(1024 * 1024)
    except OSError as e:
        report["guidance"] = f"Could not read file: {e}"
        return report

    report["overall_entropy"] = round(shannon_entropy(head[:65536]), 3)
    report["high_entropy"] = report["overall_entropy"] > 7.2

    found = {}  # name -> automatable

    # 1. Section-name signatures (via LIEF).
    try:
        loader = UniversalLoader()
        loader.load(path)
        parsed = getattr(loader, "parsed", None)
        if parsed is not None:
            for s in getattr(parsed, "sections", []) or []:
                name = str(getattr(s, "name", "")).strip().lower()
                if name in SECTION_SIGNATURES:
                    pname, auto = SECTION_SIGNATURES[name]
                    found.setdefault(pname, auto)
                    report["protections"].append(
                        {"name": pname, "evidence": f"section '{name}'", "automatable": auto})
    except Exception:
        pass

    # 2. Raw byte signatures (fallback / corroboration).
    for sig, (pname, auto) in BYTE_SIGNATURES:
        if sig in head and pname not in found:
            found[pname] = auto
            report["protections"].append(
                {"name": pname, "evidence": f"byte signature {sig!r}", "automatable": auto})

    # 3. Entropy-only heuristic when nothing matched.
    if not found and report["high_entropy"]:
        report["protections"].append({
            "name": "Unknown packer/encryption",
            "evidence": f"very high entropy ({report['overall_entropy']})",
            "automatable": False,
        })

    # Verdict.
    names = [p["name"] for p in report["protections"]]
    report["automatable"] = any(p["automatable"] for p in report["protections"])
    if any(n in HEAVY for n in names):
        report["level"] = "heavy"
        report["guidance"] = (
            "Commercial protector detected. These are designed to resist automated "
            "unpacking; expect manual work (dynamic unpacking, OEP finding, dumping). "
            "No tool defeats these automatically.")
    elif report["automatable"]:
        report["level"] = "light"
        report["guidance"] = "Known packer with automated unpacking available (try 'Auto-unpack')."
    elif report["protections"]:
        report["level"] = "medium"
        report["guidance"] = ("Packed/encrypted, but no automated unpacker is available for it. "
                              "Try dynamic unpacking (run + dump) or manual analysis.")
    else:
        report["level"] = "none"
        report["guidance"] = "No packing/protection signatures detected."
    return report


def auto_unpack(path, output_path=None):
    """Automatically unpack the cases that are genuinely automatable (UPX).

    Returns the path to the unpacked file on success, else None.
    """
    report = detect_protections(path)
    is_upx = any(p["name"] == "UPX" for p in report["protections"])
    if not is_upx:
        return None
    upx = shutil.which("upx")
    if not upx:
        return None
    output_path = output_path or (path + ".unpacked")
    try:
        shutil.copyfile(path, output_path)
        result = subprocess.run([upx, "-d", output_path],
                                capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and os.path.exists(output_path):
            return output_path
        os.path.exists(output_path) and os.remove(output_path)
    except Exception:
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass
    return None


def render_protection_report(report):
    lines = [f"Protection level: {report['level'].upper()}",
             f"Entropy: {report['overall_entropy']}"
             + ("  ⚠ high (packed/encrypted likely)" if report["high_entropy"] else "")]
    if report["protections"]:
        lines.append("Detected:")
        for p in report["protections"]:
            tag = "auto-unpackable" if p["automatable"] else "manual only"
            lines.append(f"  - {p['name']}  [{tag}]  ({p['evidence']})")
    else:
        lines.append("Detected: none")
    lines.append(f"Guidance: {report['guidance']}")
    return "\n".join(lines)
