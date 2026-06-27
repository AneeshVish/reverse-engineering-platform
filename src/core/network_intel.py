"""Network intelligence: local machine IP(s) and resolving server hostnames to IPs.

Endpoint detection finds the *hosts/URLs* an app talks to (from its strings/source);
this resolves those hosts to concrete server IP addresses, and reports the local
machine's IP — answering "what server IP does it hit, and what's my local IP".
"""

import re
import socket

_URL_HOST = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.\-]+)", re.IGNORECASE)


def hosts_from_urls(urls):
    """Extract unique hostnames from a list of URL strings (the reliable signal)."""
    hosts = []
    for u in urls:
        m = _URL_HOST.match(u) or _URL_HOST.search(u)
        if m:
            h = m.group(1).strip(".")
            if "." in h and h not in hosts:
                hosts.append(h)
    return hosts


def local_ips():
    """Best-effort list of this machine's non-loopback IPv4 addresses."""
    ips = set()
    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    # Primary outbound interface (no traffic actually sent for UDP connect()).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ip for ip in ips if ip and not ip.startswith("127."))


def resolve_host(host, timeout=3.0):
    """Resolve a hostname to a sorted list of IPs (v4+v6). Empty on failure."""
    ips = set()
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        for res in socket.getaddrinfo(host, None):
            ips.add(res[4][0])
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old)
    return sorted(ips)


def resolve_endpoints(hosts, limit=25, timeout=3.0):
    """Resolve up to `limit` unique hostnames -> {host: [ips]} (only successes)."""
    out = {}
    for h in list(dict.fromkeys(hosts))[:limit]:
        ips = resolve_host(h, timeout)
        if ips:
            out[h] = ips
    return out


def format_network_intel(local, resolved):
    lines = ["Network Intelligence", "=" * 30]
    lines.append("Local machine IP(s): " + (", ".join(local) if local else "unknown"))
    if resolved:
        lines.append("")
        lines.append("Server endpoints (resolved hostname -> IP):")
        for host, ips in resolved.items():
            lines.append(f"  {host}  ->  {', '.join(ips)}")
    else:
        lines.append("No server hostnames resolved (offline, or none found).")
    return "\n".join(lines)
