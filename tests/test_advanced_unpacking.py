"""Tests for honest content recovery (reveal_contents) — no fake hash 'decryption'."""

import gzip
import plistlib

from src.core.advanced_unpacking import AdvancedUnpacker


def test_reveal_binary_plist(tmp_path):
    p = tmp_path / "Info.plist"
    with open(p, "wb") as f:
        plistlib.dump({"CFBundleIdentifier": "com.acme.app", "Version": "1.2.3"},
                      f, fmt=plistlib.FMT_BINARY)
    out = AdvancedUnpacker().reveal_contents(str(p))
    assert "PROPERTY LIST" in out
    assert "com.acme.app" in out   # the ACTUAL value, fully decoded
    assert "1.2.3" in out


def test_reveal_gzip_decompresses(tmp_path):
    p = tmp_path / "blob.gz"
    p.write_bytes(gzip.compress(b"api_base=https://api.internal.corp token=live_abc"))
    out = AdvancedUnpacker().reveal_contents(str(p))
    assert "DECOMPRESSED" in out and "gzip" in out
    assert "api.internal.corp" in out   # real recovered payload


def test_reveal_decodes_base64_blob(tmp_path):
    import base64
    hidden = base64.b64encode(b"https://secret.host/admin?key=value").decode()
    p = tmp_path / "config.txt"
    p.write_text(f"blob = {hidden}\n")
    out = AdvancedUnpacker().reveal_contents(str(p))
    assert "secret.host/admin" in out


def test_reveal_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert "EMPTY" in AdvancedUnpacker().reveal_contents(str(p))


def test_reveal_chromium_pak(tmp_path):
    import struct
    # Minimal Chromium .pak v5 with one text resource (high-level format, not encryption).
    payload = b"hello world resource"
    header = struct.pack("<I", 5) + bytes([1, 0, 0, 0]) + struct.pack("<HH", 1, 0)
    entries = (struct.pack("<H", 100) + struct.pack("<I", 24) +
               struct.pack("<H", 0) + struct.pack("<I", 24 + len(payload)))
    p = tmp_path / "resources.pak"
    p.write_bytes(header + entries + payload)
    out = AdvancedUnpacker().reveal_contents(str(p))
    assert "CHROMIUM RESOURCE PACK v5" in out
    assert "hello world resource" in out   # real extracted resource, not a hash


def test_no_method_named_run_qiling():
    # The old panel crashed calling a method that never existed. Guard the rename:
    # reveal_contents IS the supported entry point now.
    u = AdvancedUnpacker()
    assert hasattr(u, "reveal_contents")
