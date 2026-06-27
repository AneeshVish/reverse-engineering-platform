"""Tests for live socket-table connection capture."""

from src.core import live_connections as lc


def test_available_returns_bool():
    assert isinstance(lc.available(), bool)


def test_unknown_app_returns_empty():
    # An app that is certainly not running yields no connections (and never raises).
    assert lc.live_connections("no-such-app-zzz-12345") == []


def test_format_empty():
    txt = lc.format_live_connections("Spotify", [])
    assert "none found" in txt.lower()
    assert "Spotify" in txt


def test_format_with_connections():
    conns = [{"command": "Spotify", "pid": "597", "user": "ani",
              "laddr": "192.168.0.115:50147", "raddr": "35.186.224.24:443",
              "state": "ESTABLISHED"}]
    txt = lc.format_live_connections("Spotify", conns)
    assert "35.186.224.24:443" in txt
    assert "NOT DNS" in txt
    assert "50147" in txt
