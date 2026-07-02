"""Tests for the honest protection verdict (Task 2: encrypted vs. hashed/compressed/etc)."""

import gzip
import zipfile
import io

from src.core import protection_verdict as pv


def test_plaintext_macho_stub_is_not_encrypted():
    # Mach-O 64-bit magic + low-entropy padding == the Claude launcher-stub case.
    data = b"\xcf\xfa\xed\xfe" + b"\x00" * 4096
    v = pv.verdict_for_bytes(data, "Claude")
    assert v.label == pv.PLAINTEXT_CODE
    assert v.recoverable
    assert "NOT encrypted" in v.headline


def test_gzip_is_compressed_not_encrypted():
    data = gzip.compress(b"hello world" * 100)
    v = pv.verdict_for_bytes(data, "blob.gz")
    assert v.label == pv.COMPRESSED
    assert v.recoverable


def test_zip_archive_detected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", "hi")
    v = pv.verdict_for_bytes(buf.getvalue(), "app.asar")
    assert v.label == pv.ARCHIVE
    assert v.recoverable


def test_readable_source():
    v = pv.verdict_for_bytes(b"function f(){ return 1; }\n" * 50, "app.js")
    assert v.label in (pv.SCRIPT_SOURCE, pv.MINIFIED)
    assert v.recoverable


def test_minified_js_flagged():
    # One enormous line of valid-looking JS == minified bundle.
    data = b"var a=1;" + b"b=b+1;" * 5000
    v = pv.verdict_for_bytes(data, "main.min.js")
    assert v.label == pv.MINIFIED
    assert v.recoverable


def test_der_certificate_is_signed_not_encrypted():
    data = b"\x30\x82\x01\x00" + b"\x00" * 300   # DER SEQUENCE header
    v = pv.verdict_for_bytes(data, "embedded.provisionprofile")
    assert v.label == pv.SIGNED
    assert v.recoverable


def test_high_entropy_unknown_is_encrypted_likely():
    import os
    data = os.urandom(200_000)   # near-max entropy, no known magic
    v = pv.verdict_for_bytes(data, "mystery.bin")
    assert v.label == pv.ENCRYPTED_LIKELY
    assert not v.recoverable
    assert "key" in v.render().lower()


def test_png_media():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 500
    v = pv.verdict_for_bytes(data, "icon.png")
    assert v.label == pv.IMAGE_MEDIA
    assert v.recoverable


def test_empty():
    v = pv.verdict_for_bytes(b"", "empty")
    assert v.label == pv.UNKNOWN
