"""Tests for region probe and network fingerprint."""

from src.core import network_fingerprint as nf


def test_fingerprint_returns_structure():
    # May fail DNS in CI — structure should still be dict
    fp = nf.fingerprint_host("example.com")
    assert "host" in fp
    assert fp["host"] == "example.com"


def test_format_report():
    text = nf.format_report({"host": "x.com", "ip": "1.2.3.4", "cloud_hint": "AWS"})
    assert "x.com" in text
