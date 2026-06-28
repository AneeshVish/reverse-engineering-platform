"""Tests for the endpoint-evidence layer: TLS identity, trackers, PII, correlation.

These are offline/unit tests — no live TLS handshake or WHOIS (those are exercised
manually against real hosts). They cover the pure parsing/matching/formatting logic.
"""

from src.core import tls_identity as tid
from src.core import tracker_list as tl
from src.core import pii_classify as pii
from src.core import endpoint_correlation as ec


# --- tls_identity --------------------------------------------------------------

def test_registrable_domain():
    assert tid._registrable_domain("api.spotify.com") == "spotify.com"
    assert tid._registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert tid._registrable_domain("localhost") == "localhost"


def test_host_matches_wildcard():
    assert tid._host_matches("api.spotify.com", ["*.spotify.com"])
    assert tid._host_matches("spotify.com", ["spotify.com", "*.spotify.com"])
    # wildcard must not match a deeper sub-domain
    assert not tid._host_matches("a.b.spotify.com", ["*.spotify.com"])
    assert not tid._host_matches("evil.com", ["*.spotify.com"])


def test_format_proof_renders_verdict():
    proof = {
        "host": "api.spotify.com", "ip": "35.1.2.3", "ptr": "", "ip_owner": "Google LLC",
        "domain": "spotify.com", "registrant": "Spotify AB", "host_matches_cert": True,
        "verdict": "CONFIRMED — ...", "confidence": "confirmed",
        "cert": {"subject_cn": "*.spotify.com", "san": ["*.spotify.com", "spotify.com"],
                 "issuer_org": "DigiCert Inc", "validated": True, "time_valid": True,
                 "not_before": "2026-01-01", "not_after": "2027-01-01"},
    }
    out = tid.format_proof(proof)
    assert "api.spotify.com" in out
    assert "Spotify AB" in out
    assert "DigiCert" in out
    assert "VERDICT: CONFIRMED" in out
    assert "openssl s_client" in out   # independently verifiable


# --- tracker_list --------------------------------------------------------------

def test_tracker_classification():
    assert tl.is_tracker("app-measurement.com")
    assert tl.classify("api.amplitude.com").startswith("analytics")
    assert tl.classify("graph.facebook.com").startswith("social-tracker")
    assert tl.classify("api.spotify.com") == ""        # first-party, not a tracker


def test_tracker_summary():
    hosts = ["api.spotify.com", "app-measurement.com", "graph.facebook.com"]
    out = tl.summarize(hosts)
    assert "2 of 3" in out
    assert "app-measurement.com" in out


# --- pii_classify --------------------------------------------------------------

def test_pii_detects_identifiers_and_tokens():
    body = (b'{"email":"a@b.com","advertising_id":"123e4567-e89b-12d3-a456-426614174000",'
            b'"access_token":"xyz","lat":37.77,"device_id":"abc"}')
    labels = {h[0] for h in pii.find_pii(body)}
    assert "Email address" in labels
    assert "Auth token / session" in labels
    assert any("advertising" in l.lower() or "UUID" in l for l in labels)
    assert any("location" in l.lower() or "GPS" in l for l in labels)


def test_pii_empty_body():
    assert pii.find_pii(b"") == []
    assert pii.find_pii(None) == []


def test_pii_critical_sorts_first():
    body = b'{"username":"bob","access_token":"x"}'
    hits = pii.find_pii(body)
    assert hits[0][1] == "critical"   # token outranks username


# --- endpoint_correlation ------------------------------------------------------

def test_host_normalization():
    assert ec.host_of("https://api.spotify.com/v1/me") == "api.spotify.com"
    assert ec.host_of("35.1.2.3:443") == "35.1.2.3"
    assert ec.host_of("API.Spotify.COM") == "api.spotify.com"


def test_correlation_tags():
    rows = ec.correlate(
        static_hosts=["api.spotify.com", "unused.spotify.com"],
        live_hosts=["https://api.spotify.com/x", "app-measurement.com"])
    by_host = {r["host"]: r for r in rows}
    assert by_host["api.spotify.com"]["status"] == "confirmed"
    assert by_host["unused.spotify.com"]["status"] == "predicted-only"
    assert by_host["app-measurement.com"]["status"] == "live-only"
    assert by_host["app-measurement.com"]["tracker"]      # flagged as tracker
    # confirmed sorts first
    assert rows[0]["status"] == "confirmed"


def test_correlation_format():
    rows = ec.correlate(["api.spotify.com"], ["api.spotify.com"])
    out = ec.format_correlation(rows)
    assert "1/1 endpoints CONFIRMED" in out
