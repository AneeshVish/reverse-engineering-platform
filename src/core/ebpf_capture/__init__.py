"""eBPF kernel TLS capture (Linux, BCC uprobes on OpenSSL)."""

from src.core.ebpf_capture.sniffer import eBPFSniffer, available as sniffer_available
from src.core.ebpf_capture.lib_resolver import resolve_ssl_library

__all__ = ["eBPFSniffer", "sniffer_available", "resolve_ssl_library"]
