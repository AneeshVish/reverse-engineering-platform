"""Live network connections of a running app — the non-googleable signal.

Static analysis can only list hostnames embedded in a binary (which anyone can
also get with `strings` + `dig`). This reads the OS socket table to show what a
RUNNING app is actually connected to right now: real remote IP:port pairs, with
the local source port — specific to this app, this machine, this moment.

Uses `lsof` (works for the current user's own processes without sudo on macOS and
Linux). Returns [] cleanly if lsof is unavailable or the app isn't running.
"""

import shutil
import socket
import subprocess


def available():
    return shutil.which("lsof") is not None


def reverse_dns(ip):
    """PTR hostname for an IP — proves whose infrastructure it is (cloud/CDN/org)."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def whois_org(ip):
    """Owner organization for an IP via the `whois` command (definitive proof)."""
    w = shutil.which("whois")
    if not w:
        return ""
    try:
        out = subprocess.run([w, ip], capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""
    import re
    for key in ("OrgName", "org-name", "Organization", "organisation", "owner", "netname"):
        m = re.search(rf"(?im)^{key}:\s*(.+)$", out)
        if m:
            val = m.group(1).strip()
            if val and "administered by" not in val.lower():
                return val
    return ""


def _org_hint(host):
    """Best-effort owner hint from a PTR hostname."""
    h = host.lower()
    table = [
        ("anthropic", "Anthropic"), ("googleusercontent", "Google Cloud"),
        ("1e100.net", "Google"), ("amazonaws", "AWS"), ("aws", "AWS"),
        ("cloudfront", "AWS CloudFront"), ("azure", "Microsoft Azure"),
        ("cloudflare", "Cloudflare"), ("fastly", "Fastly"), ("akamai", "Akamai"),
        ("apple", "Apple"), ("spotify", "Spotify"), ("discord", "Discord"),
        ("openai", "OpenAI"), ("github", "GitHub"),
    ]
    for needle, org in table:
        if needle in h:
            return org
    return ""


def live_connections(app_name, established_only=True, limit=300):
    """Return live TCP connections for processes whose command matches app_name.

    Each item: {command, pid, user, laddr, raddr, state}.
    """
    lsof = shutil.which("lsof")
    if not lsof or not app_name:
        return []
    cmd = [lsof, "-nP", "-iTCP"]
    if established_only:
        cmd += ["-sTCP:ESTABLISHED"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
    except Exception:
        return []

    # lsof truncates the COMMAND column (~9 chars), so match a short key.
    key = app_name.lower()[:9]
    conns = []
    seen = set()
    for line in out.stdout.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid, user = parts[0], parts[1], parts[2]
        namecol = parts[8]
        if key not in command.lower():
            continue
        if "->" not in namecol:
            continue
        laddr, rest = namecol.split("->", 1)
        bits = rest.split(" ", 1)
        raddr = bits[0]
        state = ""
        if len(bits) > 1 and "(" in bits[1]:
            state = bits[1].strip().strip("()")
        dedup = (command, laddr, raddr)
        if dedup in seen:
            continue
        seen.add(dedup)
        conns.append({"command": command, "pid": pid, "user": user,
                      "laddr": laddr, "raddr": raddr, "state": state or "ESTABLISHED"})
        if len(conns) >= limit:
            break

    # Reverse-DNS each unique remote IP (off the UI thread already) to prove whose
    # infrastructure the app is talking to.
    rdns_cache = {}
    for c in conns:
        ip = c["raddr"].rsplit(":", 1)[0]
        if ip not in rdns_cache:
            host = reverse_dns(ip)
            org = _org_hint(host) or whois_org(ip)   # PTR org, else WHOIS owner
            rdns_cache[ip] = (host, org)
        c["rdns"], c["org"] = rdns_cache[ip]
    return conns


def format_live_connections(app_name, conns):
    if not conns:
        return (f"LIVE connections: none found.\n"
                f"(Is {app_name} running? lsof only sees your own processes; "
                f"open the app and click Re-analyze.)")
    lines = [f"LIVE connections — what {app_name} is ACTUALLY talking to right now",
             "(read from the OS socket table — NOT DNS; you cannot get this by googling):",
             ""]
    # Group by remote IP for a clean view.
    remotes = {}
    for c in conns:
        remotes.setdefault(c["raddr"], []).append(c)
    for raddr, items in remotes.items():
        c = items[0]
        locals_ = ", ".join(sorted({i["laddr"] for i in items})[:4])
        owner = ""
        if c.get("org"):
            owner = f"  [{c['org']}]"
        elif c.get("rdns"):
            owner = f"  [{c['rdns']}]"
        lines.append(f"  -> {raddr}{owner}")
        host = c.get("rdns")
        if host and c.get("org"):
            lines.append(f"       PTR: {host}")
        lines.append(f"       ({c['command']} pid {c['pid']};  local {locals_})")
    lines.append("")
    lines.append("[Owner] is derived from the IP's reverse-DNS (PTR) record and WHOIS "
                 "registration — independent proof of whose servers these are, tied to "
                 "the live sockets above. Cross-check any line with `whois <ip>`.")
    return "\n".join(lines)
