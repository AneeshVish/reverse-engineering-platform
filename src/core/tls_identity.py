"""TLS identity + endpoint ownership PROOF.

Turns an endpoint *address* into *proof of who operates it*. Performs a normal TLS
handshake (exactly what a browser does) to read the server's certificate, then
composes a verifiable ownership chain:

    DNS name  ->  server IP  ->  TLS certificate (CN/SAN, issuer, validity)
              ->  IP-WHOIS (hosting org)  ->  domain-WHOIS (registrant)

Every line is independently checkable with `openssl s_client`, `dig`, and `whois`,
so the proof does not require trusting our tool. A CA-trusted certificate that is
valid for the hostname is cryptographic proof the server is authorized to operate
that domain — that is how "this server owns the backend" is actually established.
"""

import datetime
import re
import socket
import ssl
import subprocess
import shutil

# A few multi-label public suffixes so api.example.co.uk -> example.co.uk.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.in", "co.nz", "com.br", "com.cn", "co.kr",
}


def _registrable_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) < 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:]) if len(parts) >= 3 else last2
    if ".".join(parts[-2:]) in _MULTI_SUFFIXES and len(parts) >= 3:
        return last3
    return last2


def _host_matches(host, names):
    """True if host matches any cert name (supports a single leading wildcard)."""
    host = host.lower()
    for raw in names:
        if not raw:
            continue
        name = raw.lower()
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


def _parse_cert(der):
    from cryptography import x509
    out = {"subject_cn": "", "subject_org": "", "issuer": "", "issuer_org": "", "san": []}
    cert = x509.load_der_x509_certificate(der)
    NameOID = x509.NameOID
    for field, src, oid in (
        ("subject_cn", cert.subject, NameOID.COMMON_NAME),
        ("subject_org", cert.subject, NameOID.ORGANIZATION_NAME),
        ("issuer", cert.issuer, NameOID.COMMON_NAME),
        ("issuer_org", cert.issuer, NameOID.ORGANIZATION_NAME),
    ):
        try:
            vals = src.get_attributes_for_oid(oid)
            out[field] = vals[0].value if vals else ""
        except Exception:
            pass
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out["san"] = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        out["san"] = []
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        tz = datetime.timezone.utc
        nb = cert.not_valid_before.replace(tzinfo=tz)
        na = cert.not_valid_after.replace(tzinfo=tz)
    out["not_before"] = nb.isoformat()
    out["not_after"] = na.isoformat()
    out["time_valid"] = nb <= datetime.datetime.now(datetime.timezone.utc) <= na
    return out


def fetch_certificate(host, port=443, timeout=6.0):
    """TLS-handshake to host:port and return the server certificate details.

    Records whether the certificate VALIDATED (CA-trusted + hostname match) and,
    either way, parses the presented certificate so we can show what it claims.
    """
    result = {"host": host, "port": port, "validated": False, "tls_version": "", "error": ""}
    der = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                result["validated"] = True
                result["tls_version"] = ss.version()
                der = ss.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"did not validate: {e}"
    except Exception as e:
        result["error"] = str(e)

    if der is None:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    result["tls_version"] = result["tls_version"] or ss.version()
                    der = ss.getpeercert(binary_form=True)
        except Exception as e:
            if not result["error"]:
                result["error"] = str(e)
            return result

    if der:
        try:
            result.update(_parse_cert(der))
        except Exception as e:
            result["error"] = result["error"] or f"parse failed: {e}"
    return result


def domain_registrant(domain):
    """Registrant org / registrar for a DOMAIN via `whois` (best-effort)."""
    w = shutil.which("whois")
    if not w or not domain:
        return ""
    try:
        out = subprocess.run([w, domain], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""
    for key in ("Registrant Organization", "Registrant Name", "Registrar",
                "Registrant", "org"):
        m = re.search(rf"(?im)^\s*{re.escape(key)}:\s*(.+)$", out)
        if m:
            val = m.group(1).strip()
            if val and "redacted" not in val.lower() and "privacy" not in val.lower():
                return val
    return ""


def ownership_proof(host, port=443):
    """Build the full ownership-evidence chain for one endpoint host."""
    from src.core.live_connections import reverse_dns, whois_org

    proof = {"host": host, "ip": "", "ip_owner": "", "ptr": "",
             "domain": "", "registrant": "", "host_matches_cert": False}
    try:
        proof["ip"] = socket.gethostbyname(host)
    except Exception:
        proof["ip"] = ""
    proof["cert"] = fetch_certificate(host, port)

    cert = proof["cert"]
    names = list(cert.get("san", []))
    if cert.get("subject_cn"):
        names.append(cert["subject_cn"])
    proof["host_matches_cert"] = _host_matches(host, names)

    if proof["ip"]:
        proof["ip_owner"] = whois_org(proof["ip"])
        proof["ptr"] = reverse_dns(proof["ip"])
    proof["domain"] = _registrable_domain(host)
    proof["registrant"] = domain_registrant(proof["domain"])

    if cert.get("validated") and proof["host_matches_cert"]:
        proof["verdict"] = (
            f"CONFIRMED — the server presents a CA-trusted certificate valid for "
            f"{host}. Cryptographic proof it is authorized to operate this endpoint.")
        proof["confidence"] = "confirmed"
    elif cert.get("san") and proof["host_matches_cert"]:
        proof["verdict"] = (
            f"LIKELY — certificate names cover {host} but did not fully chain to a "
            f"trusted CA here ({cert.get('error', 'see error')}).")
        proof["confidence"] = "likely"
    elif cert.get("san"):
        proof["verdict"] = (
            f"MISMATCH — server presented a certificate for {', '.join(cert['san'][:3])}, "
            f"which does not cover {host}.")
        proof["confidence"] = "mismatch"
    else:
        proof["verdict"] = f"UNPROVEN — could not retrieve a certificate ({cert.get('error', '')})."
        proof["confidence"] = "unproven"
    return proof


def format_proof(proof):
    """Render an ownership proof-card for one endpoint."""
    cert = proof.get("cert", {})
    lines = [f"ENDPOINT OWNERSHIP PROOF — {proof['host']}",
             f"  Resolves to:   {proof.get('ip') or '(no DNS)'}"]
    if proof.get("ptr"):
        lines.append(f"  Reverse DNS:   {proof['ptr']}")
    if proof.get("ip_owner"):
        lines.append(f"  IP owner:      {proof['ip_owner']}  (hosting/network)")
    if cert.get("subject_cn") or cert.get("san"):
        lines.append(f"  TLS cert CN:   {cert.get('subject_cn') or '(none)'}")
        if cert.get("san"):
            lines.append(f"  Cert SAN:      {', '.join(cert['san'][:6])}"
                         + (" …" if len(cert["san"]) > 6 else ""))
        issuer = cert.get("issuer_org") or cert.get("issuer") or "?"
        lines.append(f"  Issued by:     {issuer}")
        lines.append(f"  Valid window:  {cert.get('not_before', '?')} → {cert.get('not_after', '?')}"
                     f"  ({'in date' if cert.get('time_valid') else 'OUT OF DATE'})")
        lines.append(f"  Validates:     {'yes (CA-trusted + hostname match)' if cert.get('validated') else 'no — ' + cert.get('error', '')}")
    if proof.get("registrant"):
        lines.append(f"  Domain owner:  {proof['registrant']}  (registrant of {proof['domain']})")
    lines.append("")
    lines.append(f"  VERDICT: {proof.get('verdict', '')}")
    lines.append("  Verify yourself:  "
                 f"openssl s_client -connect {proof['host']}:443 -servername {proof['host']}  |  "
                 f"whois {proof.get('domain', proof['host'])}")
    return "\n".join(lines)
