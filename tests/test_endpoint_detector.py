"""Tests for network endpoint detection (string/symbol based, not instruction shapes)."""

from src.intelligence.endpoint_detector import (
    detect_endpoints, extract_strings, format_endpoint_results,
)


def _cats(found):
    from collections import Counter
    return Counter(e.category for e in found)


def test_disassembly_noise_is_not_flagged():
    """Regression: raw instructions must NOT be reported as network endpoints."""
    noise = b"\n".join([
        b"100002329: call qword ptr [rax + 0x10]",
        b"1000023b6: call qword ptr [rax + 0x20]",
        b"100002400: mov esi, 1",
        b"100002410: mov ebx, 3",
        b"100002420: jmp qword ptr [rcx + 0x8]",
    ] * 500)   # 2500 instruction lines
    found = detect_endpoints(noise)
    assert found == []     # zero false positives, not thousands


def test_detects_real_indicators():
    blob = (b"junk\x00https://api.example.com/login\x00 8.8.8.8 \x00"
            b"evil-domain.net\x00socket\x00getaddrinfo\x00SSL_connect\x00")
    found = detect_endpoints(blob)
    values = {e.content for e in found}
    assert "https://api.example.com/login" in values
    assert "8.8.8.8" in values
    assert "evil-domain.net" in values
    assert "getaddrinfo" in values
    assert "SSL_connect" in values


def test_invalid_ip_not_detected():
    # 999.1.1.1 is not a valid IPv4 address.
    found = detect_endpoints(b"version 999.1.1.1 and 256.0.0.1 here")
    assert not any(e.category == "IPv4 address" for e in found)


def test_ipv6_validated():
    found = detect_endpoints(b"addr 2001:4860:4860::8888 end")
    assert any(e.category == "IPv6 address" and e.content == "2001:4860:4860::8888"
               for e in found)


def test_empty_and_format():
    assert detect_endpoints(b"nothing interesting here at all") == []
    assert "No network endpoints" in format_endpoint_results([])


def test_extract_strings():
    s = extract_strings(b"\x00\x01ab\x00hello world\xffmore")
    assert "hello world" in s


def test_weak_apis_low_confidence():
    found = detect_endpoints(b"please connect and accept the terms")
    weak = [e for e in found if e.content in ("connect", "accept")]
    assert all(e.confidence < 0.5 for e in weak)
