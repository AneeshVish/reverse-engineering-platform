"""PyGhidra BoringSSL offset auto-discovery for Frida script injection."""

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

TARGET_SYMBOLS = (
    "ssl_crypto_x509_session_verify_cert_chain",
    "SSL_verify_peer_cert_chain",
    "ssl_verify_peer_cert",
)


def available() -> bool:
    from src.core import capabilities
    return capabilities.probe_pyghidra()


def auto_discover_boringssl_offset(bin_path: str) -> int:
    """Return RVA offset for BoringSSL verify function, or -1."""
    if not os.path.isfile(bin_path):
        return -1
    if not available():
        return _fallback_string_scan(bin_path)
    try:
        import pyghidra
        with pyghidra.open_program(bin_path) as flat_api:
            program = flat_api.getCurrentProgram()
            symbol_table = program.getSymbolTable()
            image_base = program.getImageBase().getOffset()
            for name in TARGET_SYMBOLS:
                for sym in symbol_table.getSymbols(name):
                    rva = sym.getAddress().getOffset() - image_base
                    if rva >= 0:
                        return int(rva)
    except Exception as e:
        logger.debug("PyGhidra offset discovery failed: %s", e)
    return _fallback_string_scan(bin_path)


def _fallback_string_scan(bin_path: str) -> int:
    """Best-effort scan for verify-related symbol strings in binary."""
    try:
        with open(bin_path, "rb") as f:
            data = f.read()
        for name in TARGET_SYMBOLS:
            idx = data.find(name.encode("ascii"))
            if idx >= 0:
                return idx
    except OSError:
        pass
    return -1


def render_frida_script(bin_path: str, module_name: str = "libflutter.so") -> str:
    """Fill boringssl_hook.js.template with discovered offset."""
    from src.utils.paths import project_root
    template_path = os.path.join(project_root(), "assets", "frida", "boringssl_hook.js.template")
    offset = auto_discover_boringssl_offset(bin_path)
    try:
        with open(template_path, encoding="utf-8") as f:
            tpl = f.read()
    except OSError:
        return ""
    return tpl.replace("{{SSL_VERIFY_OFFSET}}", str(offset)).replace(
        "{{MODULE_NAME}}", module_name
    )
