"""Tests for the re-sign-a-copy helper (make a hardened macOS app instrumentable).

Pure logic (entitlements content, command construction, bundle validation) is
tested everywhere. The real ditto+codesign round-trip is an integration test that
runs only on macOS with the tools present.
"""

import os
import plistlib
import sys

import pytest

from src.core import resign


# --- pure logic (all platforms) -------------------------------------------

def test_entitlements_include_get_task_allow():
    ent = plistlib.loads(resign.entitlements_plist_bytes())
    assert ent["com.apple.security.get-task-allow"] is True
    assert ent["com.apple.security.cs.disable-library-validation"] is True
    assert ent["com.apple.security.cs.allow-unsigned-executable-memory"] is True


def test_entitlements_accepts_extra():
    ent = plistlib.loads(resign.entitlements_plist_bytes(
        {"com.apple.security.cs.allow-jit": False, "custom.key": True}))
    assert ent["custom.key"] is True
    assert ent["com.apple.security.cs.allow-jit"] is False   # override wins


def test_sign_command_shape():
    cmd = resign.sign_command("/tmp/X.app", "/tmp/ent.plist", identity="-")
    assert cmd[0] == "codesign"
    assert "--force" in cmd and "--deep" in cmd
    i = cmd.index("--sign")
    assert cmd[i + 1] == "-"                     # ad-hoc
    j = cmd.index("--entitlements")
    assert cmd[j + 1] == "/tmp/ent.plist"
    assert cmd[-1] == "/tmp/X.app"


def test_is_app_bundle(tmp_path):
    assert not resign.is_app_bundle(str(tmp_path / "nope"))
    app = tmp_path / "Demo.app"
    app.mkdir()
    assert resign.is_app_bundle(str(app))
    plain = tmp_path / "file.txt"
    plain.write_text("x")
    assert not resign.is_app_bundle(str(plain))


def test_prepare_rejects_non_bundle(tmp_path):
    f = tmp_path / "tool"
    f.write_text("x")
    res = resign.prepare_instrumentable_copy(str(f))
    assert res["ok"] is False
    assert res["copy_path"] is None


def test_available_is_bool():
    assert isinstance(resign.available(), bool)


# --- integration: real ditto + codesign round-trip (macOS only) -----------

@pytest.mark.skipif(not resign.available(), reason="macOS + codesign/ditto required")
def test_prepare_instrumentable_copy_roundtrip(tmp_path):
    # Build a minimal .app: Contents/MacOS/<exe> + Info.plist.
    app = tmp_path / "Demo.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    exe = macos / "Demo"
    # A tiny real Mach-O so codesign has something valid to sign: copy /bin/echo.
    import shutil as _sh
    _sh.copy("/bin/echo", exe)
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Demo",
                       "CFBundleIdentifier": "com.test.demo"}, f)

    dest = tmp_path / "out"
    res = resign.prepare_instrumentable_copy(str(app), dest_dir=str(dest))

    assert res["ok"] is True, res["message"]
    assert os.path.isdir(res["copy_path"])
    assert res["copy_path"] != str(app)                      # original untouched
    assert os.path.isfile(res["exe_path"])
    # The copy must actually carry the get-task-allow entitlement.
    assert resign.is_instrumentable(res["copy_path"])
    ent = resign.entitlements_of(res["copy_path"])
    assert ent.get("com.apple.security.get-task-allow") is True
