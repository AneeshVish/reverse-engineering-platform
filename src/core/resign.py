"""Make a hardened macOS app instrumentable by re-signing a COPY of it.

Modern Electron apps (Claude, Slack, …) ship with the hardened runtime, library
validation, and Electron "fuses" that disable `--inspect`, `NODE_OPTIONS`, and
DevTools — and they integrity-check their own `app.asar`. Those defenses block
DevTools/CDP and any bundle patching, and macOS refuses to let a debugger/Frida
attach to a hardened-runtime process that lacks the `get-task-allow` entitlement.

The clean, surgical bypass (for software you are authorized to analyze) is to:
  1. Copy the .app bundle (never touch the original),
  2. Re-sign the COPY, ad-hoc, adding the debugging entitlements Frida needs
     (`get-task-allow`, `disable-library-validation`, …).

Because we re-sign an UNMODIFIED asar, the asar-integrity fuse stays satisfied —
we change entitlements, not content. The result is a byte-identical app that a
local debugger/Frida can attach to.

This is macOS-only and requires the `codesign` / `ditto` command-line tools
(present on any Mac with the Command Line Tools installed).

AUTHORIZATION: only prepare apps you own or are authorized to test. This produces
a debuggable copy for LOCAL dynamic analysis; it is not a distribution artifact
and its ad-hoc signature is only valid on this machine.
"""

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile


# Entitlements that let a local debugger / Frida attach and inject into an
# otherwise-hardened process. get-task-allow is the one that actually grants
# task-port access; the others relax library validation and JIT/dyld guards that
# Frida's agent needs.
INSTRUMENTATION_ENTITLEMENTS = {
    "com.apple.security.get-task-allow": True,
    "com.apple.security.cs.disable-library-validation": True,
    "com.apple.security.cs.allow-unsigned-executable-memory": True,
    "com.apple.security.cs.allow-dyld-environment-variables": True,
    "com.apple.security.cs.allow-jit": True,
}


def available():
    """True if re-signing is possible here (macOS with codesign + ditto)."""
    return (sys.platform == "darwin"
            and shutil.which("codesign") is not None
            and shutil.which("ditto") is not None)


def is_app_bundle(path):
    return bool(path) and path.rstrip("/").endswith(".app") and os.path.isdir(path)


def entitlements_plist_bytes(extra=None):
    """Serialize the instrumentation entitlements to a plist (bytes)."""
    ent = dict(INSTRUMENTATION_ENTITLEMENTS)
    if extra:
        ent.update(extra)
    return plistlib.dumps(ent)


def _run(cmd, timeout=180):
    """Run a command; return (ok, combined_output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # FileNotFoundError, TimeoutExpired, ...
        return False, str(e)


def copy_bundle(app_path, dest):
    """Copy a .app to `dest` preserving structure/attrs (ditto). Returns dest."""
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    ok, out = _run(["ditto", app_path, dest])
    if not ok:
        raise RuntimeError(f"ditto copy failed: {out.strip()[:300]}")
    return dest


def sign_command(app_path, entitlements_path, identity="-"):
    """Build the codesign argv that re-signs the bundle with our entitlements.

    Ad-hoc identity ('-') needs no certificate and is enough for local debugging.
    --force replaces the existing signature; --deep re-signs nested code so the
    whole bundle stays consistent after we change the top-level entitlements.
    """
    return [
        "codesign", "--force", "--deep",
        "--sign", identity,
        "--entitlements", entitlements_path,
        # keep the hardened runtime flag but our entitlements now permit attaching
        "--options", "runtime",
        "--timestamp=none",
        app_path,
    ]


def entitlements_of(app_path):
    """Return the app's current entitlements dict (best-effort), else {}.

    The entitlements plist goes to stdout; codesign also prints an "Executable=…"
    banner and a deprecation warning to stderr — so we parse stdout ONLY, then
    trim to the </plist> close tag (plistlib rejects any trailing bytes).
    """
    try:
        r = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", "--xml", app_path],
            capture_output=True, text=True, timeout=60)
    except Exception:
        return {}
    out = r.stdout or ""
    start = out.find("<?xml")
    if start < 0:
        start = out.find("<plist")
    end = out.rfind("</plist>")
    if start < 0 or end < 0:
        return {}
    try:
        return plistlib.loads(out[start:end + len("</plist>")].encode("utf-8", "replace"))
    except Exception:
        return {}


def is_instrumentable(app_path):
    """True if the (already-signed) app carries the get-task-allow entitlement."""
    return bool(entitlements_of(app_path).get("com.apple.security.get-task-allow"))


def prepare_instrumentable_copy(app_path, dest_dir=None, identity="-"):
    """Copy `app_path` and re-sign the copy so Frida/lldb can attach.

    Returns a result dict:
      {ok, copy_path, exe_path, message, entitlements}
    Never raises for the expected failure modes; reports them in `message`.
    """
    result = {"ok": False, "copy_path": None, "exe_path": None,
              "message": "", "entitlements": dict(INSTRUMENTATION_ENTITLEMENTS)}

    if sys.platform != "darwin":
        result["message"] = "Re-signing is macOS-only (needs codesign)."
        return result
    if not available():
        result["message"] = ("codesign/ditto not found. Install Xcode Command Line "
                              "Tools:  xcode-select --install")
        return result
    if not is_app_bundle(app_path):
        result["message"] = f"Not a .app bundle: {app_path}"
        return result

    base = os.path.basename(app_path.rstrip("/"))
    stem = base[:-4] if base.endswith(".app") else base
    dest_dir = dest_dir or tempfile.mkdtemp(prefix="re_instrumentable_")
    copy_path = os.path.join(dest_dir, f"{stem}-instrumentable.app")

    try:
        copy_bundle(app_path, copy_path)
    except Exception as e:
        result["message"] = str(e)
        return result

    ent_path = os.path.join(dest_dir, "instrumentation.entitlements")
    try:
        with open(ent_path, "wb") as f:
            f.write(entitlements_plist_bytes())
    except OSError as e:
        result["message"] = f"Could not write entitlements: {e}"
        return result

    ok, out = _run(sign_command(copy_path, ent_path, identity))
    if not ok:
        result["copy_path"] = copy_path
        result["message"] = f"codesign failed: {out.strip()[:400]}"
        return result

    # Verify the entitlement actually took, so we never hand back a copy that
    # silently still can't be attached to.
    if not is_instrumentable(copy_path):
        result["copy_path"] = copy_path
        result["message"] = ("Re-signed, but get-task-allow is not present on the "
                             "copy — attaching may still be blocked. Check codesign "
                             "output / SIP state.")
        return result

    try:
        from src.core.bundle_analysis import resolve_app_executable
        result["exe_path"] = resolve_app_executable(copy_path)
    except Exception:
        result["exe_path"] = None

    result["ok"] = True
    result["copy_path"] = copy_path
    result["message"] = (
        f"Prepared an instrumentable copy:\n  {copy_path}\n"
        "Spawn/attach THIS copy in Runtime Crypto (Frida can now attach). The "
        "original app is untouched; this copy's ad-hoc signature is local-only.")
    return result
