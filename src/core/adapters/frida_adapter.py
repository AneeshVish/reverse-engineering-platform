"""Convert Frida runtime_crypto events to PlaintextEvent."""

import time
from typing import Any, Dict, Optional

from src.core.evidence_store import PlaintextEvent


def _bytes_from_frida(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, list):
        return bytes(data)
    return str(data).encode("utf-8", errors="replace")


def frida_event_to_plaintext(evt: Dict[str, Any]) -> Optional[PlaintextEvent]:
    if not isinstance(evt, dict):
        return None
    api = evt.get("api", "")
    op = evt.get("op", "")
    if api not in ("SSL_write", "SSL_read") and op not in ("tls-send", "tls-recv"):
        if api in ("CCCrypt", "EVP_DecryptUpdate", "EVP_EncryptUpdate", "CC_SHA256"):
            payload_type = "crypto"
        else:
            return None
    else:
        payload_type = "tls_send" if op == "tls-send" or api == "SSL_write" else "tls_recv"

    raw = _bytes_from_frida(evt.get("data"))
    pid = int(evt.get("pid") or 0)
    return PlaintextEvent(
        timestamp_ns=int(time.time_ns()),
        source_plane="frida",
        pid=pid,
        uid=0,
        process_comm=str(evt.get("comm", "") or f"pid:{pid}"),
        target_host=str(evt.get("host", "") or ""),
        target_port=int(evt.get("port") or 0),
        payload_type=payload_type,
        raw_payload=raw,
        metadata={
            "api": api,
            "op": op,
            "len": evt.get("len", len(raw)),
        },
    )
