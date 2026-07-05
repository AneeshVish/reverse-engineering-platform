"""Adapters: native capture formats → PlaintextEvent."""

from src.core.adapters.mitm_adapter import flow_to_plaintext_events
from src.core.adapters.frida_adapter import frida_event_to_plaintext
from src.core.adapters.ebpf_adapter import ebpf_event_to_plaintext

__all__ = [
    "flow_to_plaintext_events",
    "frida_event_to_plaintext",
    "ebpf_event_to_plaintext",
]
