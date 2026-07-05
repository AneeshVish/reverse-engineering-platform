"""Convert eBPF sniffer events to PlaintextEvent."""

import time
from typing import Any, Dict, Optional

from src.core.evidence_store import PlaintextEvent


def ebpf_event_to_plaintext(evt: Dict[str, Any]) -> Optional[PlaintextEvent]:
    if not isinstance(evt, dict):
        return None
    sym = evt.get("sym", "SSL_write")
    payload_type = "tls_send" if "write" in sym.lower() else "tls_recv"
    raw = evt.get("payload", b"")
    if isinstance(raw, list):
        raw = bytes(raw)
    elif not isinstance(raw, bytes):
        raw = str(raw).encode("utf-8", errors="replace")
    ts = evt.get("timestamp_ns") or int(time.time_ns())
    return PlaintextEvent(
        timestamp_ns=int(ts),
        source_plane="ebpf",
        pid=int(evt.get("pid", 0)),
        uid=int(evt.get("uid", 0)),
        process_comm=str(evt.get("comm", "") or ""),
        target_host=str(evt.get("host", "") or ""),
        target_port=int(evt.get("port") or 0),
        payload_type=payload_type,
        raw_payload=raw,
        metadata={"sym": sym, "len": evt.get("len", len(raw)), "ssl_lib": evt.get("ssl_lib", "")},
    )
