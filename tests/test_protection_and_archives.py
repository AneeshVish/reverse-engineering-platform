"""Tests for protection detection and recursive (multi-file) bundle analysis."""

import os
import struct
import zipfile
import pytest

from src.core import protection_detector as pd
from src.core import bundle_analysis as ba
from src.core.novel_binary_parser import NovelBinaryParser


def test_protection_clean_binary(tmp_path):
    # A plain text file: no protections, low entropy.
    p = tmp_path / "plain.txt"
    p.write_text("hello world, not packed")
    rep = pd.detect_protections(str(p))
    assert rep["level"] == "none"
    assert rep["protections"] == []
    assert "none" in pd.render_protection_report(rep).lower()


def test_protection_high_entropy_flagged(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(os.urandom(70000))   # random => entropy ~8
    rep = pd.detect_protections(str(p))
    assert rep["high_entropy"]
    assert rep["protections"]            # flagged as unknown packer/encryption


def test_auto_unpack_returns_none_for_non_upx(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"not packed at all")
    assert pd.auto_unpack(str(p)) is None


def test_cafebabe_disambiguation():
    parser = NovelBinaryParser()
    java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34rest"          # major version 52
    fat = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"x"  # 2 architectures
    assert parser.detect_format(java)["type"] == "JAVA"
    assert parser.detect_format(fat)["type"] == "MACHO"


def test_recursive_archive_analysis(tmp_path):
    """A zip (app) containing a source file and a nested jar must be fully walked."""
    inner_jar = tmp_path / "lib.jar"
    with zipfile.ZipFile(inner_jar, "w") as z:
        z.writestr("com/app/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34code")

    app = tmp_path / "app.apk"
    with zipfile.ZipFile(app, "w") as z:
        z.writestr("config.py", 'API_KEY = "AKIAIOSFODNN7EXAMPLE"')
        z.write(inner_jar, "lib.jar")

    results = ba.analyze_application(str(app))
    keys = list(results)
    # Walked into the apk and the nested jar.
    assert any("config.py" in k for k in keys)
    assert any("Main.class" in k and "lib.jar!" in k for k in keys)
    report = ba.summarize_bundle(results)
    assert "APPLICATION ANALYSIS SUMMARY" in report


def test_zip_slip_is_blocked(tmp_path):
    """Malicious '../' archive members must not escape the extraction dir."""
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../escape.txt", "pwned")
    dest = tmp_path / "out"
    dest.mkdir()
    ba._safe_extract(str(evil), str(dest))
    assert not (tmp_path / "escape.txt").exists()
