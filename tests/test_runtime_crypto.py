"""Tests for Runtime Crypto Capture formatting + capability gate.

The live Frida attach/spawn path needs a real target and is verified manually on an
owned process; CI exercises only the pure logic (no instrumentation, no frida import
required at runtime since `available()` tolerates its absence).
"""

from src.core import runtime_crypto as rc


def test_available_returns_bool():
    assert isinstance(rc.available(), bool)


def test_format_event_renders_key_iv_plaintext():
    evt = {
        "api": "CCCrypt", "op": "decrypt",
        "key": list(b"\x00\x11\x22\x33"),
        "iv": list(b"\xaa" * 4),
        "data": list(b'{"token":"live_x"}'),
        "len": 18,
    }
    out = rc.format_event(evt)
    assert "[CCCrypt] decrypt" in out
    assert "key (4 bytes): 00112233" in out
    assert "iv:  aaaaaaaa" in out
    assert '{"token":"live_x"}' in out          # plaintext recovered, ascii view
    assert "length: 18 bytes" in out


def test_format_capture_empty_is_honest():
    out = rc.format_capture([])
    assert "No crypto calls captured" in out
    assert "CommonCrypto" in out


def test_format_capture_multiple():
    events = [
        {"api": "EVP_DecryptUpdate", "op": "decrypt", "data": list(b"hello"), "len": 5},
        {"api": "CC_SHA256", "op": "hash-input", "data": list(b"pw"), "len": 2},
    ]
    out = rc.format_capture(events)
    assert "2 crypto call(s) intercepted" in out
    assert "EVP_DecryptUpdate" in out and "CC_SHA256" in out


def test_capture_object_constructs_without_frida():
    # Constructing the controller must never require frida to be installed.
    cap = rc.RuntimeCryptoCapture(on_event=lambda e: None)
    assert cap.events == []
