"""Multi-region probing — compare cf-ray, latency, TLS, IP across samples."""

import ssl
import socket
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from src.core.engagement_scope import engagement_manager


def probe_endpoint(url: str, region_label: str = "") -> Dict[str, Any]:
    """Fetch headers + TLS info for a URL (HEAD request)."""
    mgr = engagement_manager()
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    allowed, reason = mgr.scope.check(action="region_probe", host=host, path=path)
    if not allowed:
        return {"region": region_label, "url": url, "skipped": True, "reason": reason}

    result = {
        "region": region_label or "local",
        "url": url,
        "host": host,
        "ts": time.time(),
    }

    # TLS cert info
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            t0 = time.time()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["tls_latency_ms"] = round((time.time() - t0) * 1000, 2)
                    result["tls_issuer"] = dict(cert.get("issuer", [])) if cert else {}
                    result["tls_subject"] = dict(cert.get("subject", [])) if cert else {}
                    sans = cert.get("subjectAltName", []) if cert else []
                    result["tls_sans"] = [s[1] for s in sans if s[0] == "DNS"][:10]
        except Exception as e:
            result["tls_error"] = str(e)

    # HTTP HEAD for headers
    try:
        import urllib.request
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "RE-Platform-RegionProbe/1.0")
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=15) as resp:
            result["http_latency_ms"] = round((time.time() - t0) * 1000, 2)
            result["status"] = resp.status
            result["headers"] = {k: v for k, v in resp.headers.items()}
            for hk in ("cf-ray", "x-amz-cf-id", "x-envoy-upstream-service-time",
                       "x-request-id", "server"):
                if hk in {k.lower(): k for k in resp.headers}:
                    pass
            rh = {k.lower(): v for k, v in resp.headers.items()}
            result["cf_ray"] = rh.get("cf-ray", "")
            result["server"] = rh.get("server", "")
    except Exception as e:
        result["http_error"] = str(e)

    try:
        result["resolved_ip"] = socket.gethostbyname(host)
    except Exception:
        result["resolved_ip"] = ""

    mgr.log("region_probe", url, str(result.get("status", "tls-only")), region_label)
    return result


def compare_samples(samples: List[Dict]) -> Dict[str, Any]:
    """Diff region samples for routing/CDN evidence."""
    if len(samples) < 2:
        return {"samples": samples, "diffs": []}
    diffs = []
    base = samples[0]
    for other in samples[1:]:
        d = {"regions": (base.get("region"), other.get("region"))}
        if base.get("cf_ray") != other.get("cf_ray"):
            d["cf_ray_diff"] = (base.get("cf_ray"), other.get("cf_ray"))
        if base.get("resolved_ip") != other.get("resolved_ip"):
            d["ip_diff"] = (base.get("resolved_ip"), other.get("resolved_ip"))
        lat_a = base.get("http_latency_ms") or base.get("tls_latency_ms")
        lat_b = other.get("http_latency_ms") or other.get("tls_latency_ms")
        if lat_a and lat_b:
            d["latency_diff_ms"] = round(abs(lat_a - lat_b), 2)
        if d.keys() - {"regions"}:
            diffs.append(d)
    return {"samples": samples, "diffs": diffs}


def format_report(comparison: Dict) -> str:
    lines = ["REGION COMPARE", "=" * 60]
    for s in comparison.get("samples", []):
        if s.get("skipped"):
            lines.append(f"\n[{s.get('region')}] SKIPPED: {s.get('reason')}")
            continue
        lines.append(f"\n[{s.get('region')}] {s.get('host', '')}")
        lines.append(f"  IP: {s.get('resolved_ip', '?')}")
        lines.append(f"  cf-ray: {s.get('cf_ray', '—')}")
        lines.append(f"  latency: {s.get('http_latency_ms', s.get('tls_latency_ms', '?'))} ms")
    diffs = comparison.get("diffs", [])
    if diffs:
        lines.append(f"\nDifferences ({len(diffs)}):")
        for d in diffs:
            lines.append(f"  {d.get('regions')}: {d}")
    elif len(comparison.get("samples", [])) >= 2:
        lines.append("\nNo significant differences detected (same POP/IP?).")
    return "\n".join(lines)
