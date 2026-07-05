"""Thread-safe PlaintextEvent fan-out bus for dual-plane network capture."""

import logging
import threading
from typing import Callable, List, Optional

from src.core.evidence_store import (
    EvidenceArtifact,
    EvidenceItem,
    L1,
    OBSERVED,
    CONF_OBSERVED,
    PlaintextEvent,
    session_store,
)

logger = logging.getLogger(__name__)

_subscribers: List[Callable[[PlaintextEvent], None]] = []
_lock = threading.Lock()


def subscribe(callback: Callable[[PlaintextEvent], None]) -> None:
    with _lock:
        if callback not in _subscribers:
            _subscribers.append(callback)


def unsubscribe(callback: Callable[[PlaintextEvent], None]) -> None:
    with _lock:
        if callback in _subscribers:
            _subscribers.remove(callback)


def _payload_preview(payload: bytes, limit: int = 120) -> str:
    if not payload:
        return ""
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        text = repr(payload[:limit])
    return text[:limit].replace("\n", " ")


def _event_to_evidence(event: PlaintextEvent) -> EvidenceItem:
    host = event.target_host or "?"
    port = event.target_port or 0
    preview = _payload_preview(event.raw_payload)
    plane = event.source_plane
    ptype = event.payload_type
    claim = f"{plane} {ptype} → {host}:{port}" if host != "?" else f"{plane} {ptype}"
    detail = preview or f"{len(event.raw_payload)} bytes"
    meta = event.metadata or {}
    if meta.get("method") and meta.get("url"):
        claim = f"{meta['method']} {meta['url']}"
    return EvidenceItem(
        claim=claim,
        level=L1,
        kind=OBSERVED,
        category="network",
        confidence=CONF_OBSERVED,
        artifacts=[EvidenceArtifact(detail, source=plane)],
        source_tab="Network Capture",
        source_module="plaintext_bus",
    )


class PlaintextBus:
    """Central ingest for all TLS/plaintext capture planes."""

    def __init__(self, evidence_store=None):
        self._store = evidence_store

    @property
    def store(self):
        if self._store is None:
            self._store = session_store()
        return self._store

    def ingest(self, event: PlaintextEvent) -> PlaintextEvent:
        try:
            self.store.add(_event_to_evidence(event))
        except Exception as e:
            logger.debug("Evidence ingest failed: %s", e)

        with _lock:
            subs = list(_subscribers)
        for cb in subs:
            try:
                cb(event)
            except Exception as e:
                logger.warning("PlaintextBus subscriber error: %s", e)
        try:
            from src.api import mcp_server
            mcp_server.add_capture_event({
                "source_plane": event.source_plane,
                "payload_type": event.payload_type,
                "host": event.target_host,
                "port": event.target_port,
                "pid": event.pid,
                "len": len(event.raw_payload),
            })
        except Exception:
            pass
        return event


_bus: Optional[PlaintextBus] = None


def get_bus() -> PlaintextBus:
    global _bus
    if _bus is None:
        _bus = PlaintextBus()
    return _bus
