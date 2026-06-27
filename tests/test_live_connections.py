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


def test_reverse_dns_and_whois_return_str():
    assert isinstance(lc.reverse_dns("8.8.8.8"), str)
    assert isinstance(lc.whois_org("8.8.8.8"), str)
    assert lc._org_hint("154.66.149.34.bc.googleusercontent.com") == "Google Cloud"


def test_format_shows_owner():
    conns = [{"command": "Claude", "pid": "1", "user": "x",
              "laddr": "192.168.0.5:5000", "raddr": "1.2.3.4:443",
              "state": "ESTABLISHED", "rdns": "host.googleusercontent.com",
              "org": "Google Cloud"}]
    txt = lc.format_live_connections("Claude", conns)
    assert "Google Cloud" in txt and "1.2.3.4:443" in txt


def test_format_with_connections():
    conns = [{"command": "Spotify", "pid": "597", "user": "ani",
              "laddr": "192.168.0.115:50147", "raddr": "35.186.224.24:443",
              "state": "ESTABLISHED"}]
    txt = lc.format_live_connections("Spotify", conns)
    assert "35.186.224.24:443" in txt
    assert "NOT DNS" in txt
    assert "50147" in txt
