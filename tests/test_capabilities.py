"""Smoke tests for the capability-probe module."""

from src.core import capabilities


def test_probe_all_covers_known_keys():
    report = capabilities.probe_all()
    for key in ("ghidra", "retdec", "ollama", "mitmproxy", "angr", "frida"):
        assert key in report
        assert set(report[key]) == {"available", "name", "hint", "kind"}
        assert isinstance(report[key]["available"], bool)


def test_feature_status_unknown_key():
    available, name, hint = capabilities.feature_status("does-not-exist")
    assert available is False
    assert name == "does-not-exist"


def test_report_lines_nonempty():
    lines = capabilities.report_lines()
    assert lines and lines[0].startswith("[CAPABILITIES]")
    # Every backend should produce a status line.
    assert len(lines) >= 1 + len(capabilities.probe_all())
