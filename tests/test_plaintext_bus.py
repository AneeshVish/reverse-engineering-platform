"""Tests for PlaintextEvent bus and adapters."""

import time

from src.core.evidence_store import PlaintextEvent, session_store, reset_session_store
from src.core.plaintext_bus import PlaintextBus, get_bus
from src.core.adapters.mitm_adapter import flow_to_plaintext_events
from src.core.adapters.frida_adapter import frida_event_to_plaintext
from src.core.adapters.ebpf_adapter import ebpf_event_to_plaintext


def test_mitm_adapter_produces_request_response():
    rec = {
        "ts": time.time(),
        "method": "GET",
        "url": "https://api.example.com/v1/user",
        "host": "api.example.com",
        "path": "/v1/user",
        "status": 200,
        "req_headers": {"Authorization": "Bearer x"},
        "req_body": '{"id":1}',
        "resp_headers": {"Content-Type": "application/json"},
        "resp_body": '{"ok":true}',
    }
    events = flow_to_plaintext_events(rec)
    assert len(events) == 2
    assert events[0].source_plane == "mitmproxy"
    assert events[0].payload_type == "request"
    assert events[1].payload_type == "response"


def test_frida_adapter_tls():
    evt = {"api": "SSL_write", "op": "tls-send", "data": [72, 69, 76, 76, 79], "len": 5, "pid": 1234}
    pe = frida_event_to_plaintext(evt)
    assert pe is not None
    assert pe.source_plane == "frida"
    assert pe.payload_type == "tls_send"
    assert pe.pid == 1234


def test_ebpf_adapter():
    pe = ebpf_event_to_plaintext({
        "pid": 99, "uid": 0, "comm": "curl", "payload": b"GET /", "sym": "SSL_write",
    })
    assert pe.source_plane == "ebpf"


def test_plaintext_bus_ingest_evidence():
    reset_session_store()
    bus = PlaintextBus()
    bus.ingest(PlaintextEvent(
        timestamp_ns=1, source_plane="frida", pid=1, uid=0,
        process_comm="test", target_host="example.com", target_port=443,
        payload_type="tls_send", raw_payload=b"hello",
    ))
    items = session_store().by_category("network")
    assert len(items) >= 1
