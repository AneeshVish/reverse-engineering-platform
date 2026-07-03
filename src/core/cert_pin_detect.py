"""Certificate pinning detection in binaries and bundles."""

import re
from typing import Dict, List, Any

_PIN_PATTERNS = [
    (r"pinning|certificate.?pin|ssl.?pin", "pinning keyword"),
    (r"TrustKit|Alamofire\.SessionDelegate", "iOS pinning framework"),
    (r"okhttp3\.CertificatePinner", "OkHttp cert pinner"),
    (r"NSPinnedDomains|kSecTrustEvaluate", "Apple pinning API"),
    (r"SSL_CTX_set_cert_verify_callback", "OpenSSL verify callback"),
    (r"public.?key.?pin|sha256.?pin", "SPKI pin reference"),
]


def scan_text(text: str, source: str = "") -> List[Dict]:
    hits = []
    for pat, label in _PIN_PATTERNS:
        if re.search(pat, text, re.I):
            hits.append({"label": label, "source": source, "pattern": pat})
    return hits


def scan_bytes(data: bytes, source: str = "") -> List[Dict]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return scan_text(text, source)


def scan_path(path: str, max_size: int = 8 * 1024 * 1024) -> List[Dict]:
    import os
    hits = []
    if os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                hits.extend(scan_bytes(f.read(max_size), path))
        except OSError:
            pass
    return hits


def format_report(hits: List[Dict]) -> str:
    lines = ["CERTIFICATE PINNING DETECTION", "=" * 60]
    if not hits:
        return lines[0] + "\n" + "=" * 60 + "\nNo pinning indicators found."
    for h in hits:
        lines.append(f"  • {h['label']}  @ {h['source']}")
    lines.append("\nPinning may block MITM capture — use Runtime Crypto hooks or resign.")
    return "\n".join(lines)
