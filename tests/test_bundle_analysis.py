"""Tests for whole-application (bundle) analysis."""

import os
import pytest

from src.core import bundle_analysis as ba


def test_entropy_bounds():
    assert ba.shannon_entropy(b"") == 0.0
    assert ba.shannon_entropy(b"aaaa") == 0.0
    assert 7.0 < ba.shannon_entropy(bytes(range(256))) <= 8.0


def test_source_secret_detection(tmp_path):
    p = tmp_path / "config.py"
    p.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\npassword = "hunter2hunter2"\n')
    s = ba.analyze_binary_file(str(p))
    assert s["kind"] == "source"
    assert s["secret_hits"] >= 1
    assert not s.get("is_binary")


def test_loader_rejects_directory(tmp_path):
    from src.core.universal_loader import UniversalLoader
    assert UniversalLoader().load(str(tmp_path)) is False


def test_resolve_app_executable(tmp_path):
    # Synthesize a minimal macOS .app bundle.
    app = tmp_path / "Demo.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (macos / "Demo").write_bytes(b"\x7fELFexecutable")
    import plistlib
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Demo"}, f)
    exe = ba.resolve_app_executable(str(app))
    assert exe and exe.endswith("Contents/MacOS/Demo")


def test_resolve_app_executable_non_app(tmp_path):
    assert ba.resolve_app_executable(str(tmp_path)) is None


def test_text_file_summary(tmp_path):
    p = tmp_path / "readme.txt"
    p.write_text("just text")
    s = ba.analyze_binary_file(str(p))
    assert s["size"] == len("just text")
    assert "sha256" in s
    assert ba.render_summary(s).startswith("File:")


@pytest.mark.skipif(not os.path.exists("/bin/ls"), reason="no sample binary")
def test_binary_summary_and_bundle(tmp_path):
    import shutil
    binp = tmp_path / "tool"
    shutil.copy("/bin/ls", binp)
    (tmp_path / "config.py").write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

    results = {}
    for root, _, files in os.walk(tmp_path):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), tmp_path)
            results[rel] = ba.analyze_binary_file(os.path.join(root, f))

    binsum = results["tool"]
    assert binsum["is_binary"]
    assert binsum["sections"] > 0

    report = ba.summarize_bundle(results)
    assert "APPLICATION ANALYSIS SUMMARY" in report
    assert "Binaries: 1" in report
