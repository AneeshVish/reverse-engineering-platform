"""Runtime capability detection.

Reverse-engineering features depend on external command-line tools (Ghidra,
RetDec, Ollama, mitmproxy) and optional Python packages (angr, frida, torch...).
None of these are guaranteed to be installed. This module probes what is actually
available so the UI can *disable and explain* unavailable features instead of
letting them silently fail with an error string in a results pane.

Probing is cached: `which`/`find_spec` results don't change during a run.
"""

import functools
import importlib.util
import logging
import shutil

logger = logging.getLogger(__name__)


# External CLI tools: capability key -> (executable on PATH, human feature name,
# install hint).
EXTERNAL_TOOLS = {
    "ghidra": ("analyzeHeadless", "Ghidra decompilation",
               "Install Ghidra and add its support/ dir (analyzeHeadless) to PATH"),
    "retdec": ("retdec-decompiler", "RetDec decompilation",
               "Install RetDec and add retdec-decompiler to PATH"),
    "ollama": ("ollama", "Local AI (Ollama)",
               "Install Ollama (ollama.com) and run `ollama serve`"),
    "mitmproxy": ("mitmdump", "Network capture",
                  "pip install mitmproxy (provides the mitmdump command)"),
}

# Optional Python packages: capability key -> (import name, human feature name,
# install hint).
OPTIONAL_PACKAGES = {
    "angr": ("angr", "Symbolic execution / advanced unpacking",
             "pip install -r requirements-optional.txt  (angr)"),
    "frida": ("frida", "Dynamic instrumentation / debugger",
              "pip install -r requirements-optional.txt  (frida)"),
    "unicorn": ("unicorn", "CPU emulation",
                "pip install -r requirements-optional.txt  (unicorn)"),
    "torch": ("torch", "Local HuggingFace AI model",
              "pip install -r requirements-optional.txt  (torch, transformers)"),
    "transformers": ("transformers", "Local HuggingFace AI model",
                     "pip install -r requirements-optional.txt  (transformers)"),
}


@functools.lru_cache(maxsize=None)
def tool_available(key):
    """True if the external CLI tool for `key` is found on PATH."""
    spec = EXTERNAL_TOOLS.get(key)
    if not spec:
        return False
    return shutil.which(spec[0]) is not None


@functools.lru_cache(maxsize=None)
def package_available(key):
    """True if the optional Python package for `key` can be imported."""
    spec = OPTIONAL_PACKAGES.get(key)
    if not spec:
        return False
    try:
        return importlib.util.find_spec(spec[1]) is not None
    except (ImportError, ValueError):
        return False


def feature_status(key):
    """Return (available: bool, feature_name: str, hint: str) for any key."""
    if key in EXTERNAL_TOOLS:
        _, name, hint = EXTERNAL_TOOLS[key]
        return tool_available(key), name, hint
    if key in OPTIONAL_PACKAGES:
        _, name, hint = OPTIONAL_PACKAGES[key]
        return package_available(key), name, hint
    return False, key, "Unknown capability"


def probe_all():
    """Return {key: {available, name, hint, kind}} for every known capability."""
    report = {}
    for key in EXTERNAL_TOOLS:
        ok, name, hint = feature_status(key)
        report[key] = {"available": ok, "name": name, "hint": hint, "kind": "tool"}
    for key in OPTIONAL_PACKAGES:
        ok, name, hint = feature_status(key)
        report[key] = {"available": ok, "name": name, "hint": hint, "kind": "package"}
    return report


def report_lines():
    """Human-readable lines summarizing capability availability (for the log panel)."""
    lines = ["[CAPABILITIES] Detected analysis backends:"]
    for key, info in probe_all().items():
        mark = "OK   " if info["available"] else "MISSING"
        line = f"  [{mark}] {info['name']} ({key})"
        if not info["available"]:
            line += f"  -> {info['hint']}"
        lines.append(line)
    return lines
