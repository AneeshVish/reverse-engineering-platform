"""Network fingerprinting — DNS, TLS issuer, cloud hints."""

import re
import socket
import ssl
from typing import Dict, Any, Optional

CLOUD_IP_HINTS = [
    (r"^13\.|^52\.|^54\.|^3\.", "AWS"),
    (r"^34\.|^35\.", "Google Cloud"),
    (r"^20\.|^40\.|^104\.", "Azure"),
    (r"^104\.16\.|^172\.64\.", "Cloudflare"),
]

TLS_ISSUER_HINTS = {
    "amazon": "AWS ACM",
    "cloudflare": "Cloudflare",
    "google": "Google Trust Services",
    "lets encrypt": "Let's Encrypt",
    "digicert": "DigiCert",
}


def fingerprint_host(host: str, port: int = 443) -> Dict[str, Any]:
    result = {"host": host, "ip": "", "cloud_hint": "", "tls_issuer": "",
              "tls_sans": [], "error": ""}
    try:
        ip = socket.gethostbyname(host)
        result["ip"] = ip
        for pattern, cloud in CLOUD_IP_HINTS:
            if re.match(pattern, ip):
                result["cloud_hint"] = cloud
                break
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    issuer = cert.get("issuer", ())
                    parts = []
                    for rdn in issuer:
                        for attr, val in rdn:
                            if attr in ("organizationName", "commonName"):
                                parts.append(val)
                    result["tls_issuer"] = " / ".join(parts)
                    for hint, label in TLS_ISSUER_HINTS.items():
                        if hint in result["tls_issuer"].lower():
                            result["tls_issuer_label"] = label
                    sans = cert.get("subjectAltName", [])
                    result["tls_sans"] = [s[1] for s in sans if s[0] == "DNS"][:15]
    except Exception as e:
        result["tls_error"] = str(e)

    return result


def format_report(fp: Dict[str, Any]) -> str:
    lines = ["NETWORK FINGERPRINT", "=" * 60]
    lines.append(f"Host: {fp.get('host', '?')}")
    lines.append(f"IP: {fp.get('ip', '?')}  Cloud hint: {fp.get('cloud_hint', '—')}")
    lines.append(f"TLS issuer: {fp.get('tls_issuer', '—')}")
    if fp.get("tls_sans"):
        lines.append(f"SANs: {', '.join(fp['tls_sans'][:8])}")
    return "\n".join(lines)
