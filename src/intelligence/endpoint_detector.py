"""Network endpoint / indicator detection.

Real endpoint detection looks at the *data* in a binary — embedded strings and
referenced network APIs — not at instruction shapes. (The previous version
regex-matched raw disassembly, so things like "call qword ptr [rax+0x10]" or
"mov esi, 1" were reported as network endpoints, producing thousands of false
positives on programs with no networking at all.)

We extract printable strings and report only concrete indicators:
  * URLs (http/https/ftp/ws/wss)
  * Valid IPv4 / IPv6 addresses (validated with the `ipaddress` module)
  * Plausible domain names (label structure + known-ish TLD)
  * Calls to known network APIs (socket/connect/getaddrinfo/SSL/HTTP/CFNetwork...)
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class NetworkEndpoint:
    line_number: int          # index of the source string (best-effort)
    content: str              # the matched value
    confidence: float
    category: str
    architecture: str = "n/a"
    additional_info: Optional[Dict] = None


# Printable-ASCII runs of length >= 4 (classic "strings").
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")

_URL = re.compile(r"(?:https?|ftps?|wss?)://[^\s\"'<>\\)]{2,}", re.IGNORECASE)
_IPV4 = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])")
# IPv6 candidate (contains '::' or several ':' groups); validated below.
_IPV6_CAND = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|gov|edu|mil|co|us|uk|de|fr|ru|cn|jp|in|br|info|biz|app|dev|"
    r"cloud|ai|xyz|me|tv|sh|gg|to|ly|so|api|cdn|amazonaws|googleapis|azure)\b",
    re.IGNORECASE,
)

# Strong, unambiguous network API names (rarely appear by accident).
_STRONG_APIS = [
    "gethostbyname", "getaddrinfo", "freeaddrinfo", "inet_pton", "inet_aton",
    "getnameinfo", "res_query", "dn_expand", "getservbyname", "sendto", "recvfrom",
    "WSAStartup", "WSASocket", "WSAConnect", "closesocket",
    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
    "InternetReadFile", "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
    "SSL_connect", "SSL_CTX_new", "SSL_write", "SSL_read", "BIO_new_connect",
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "CFStreamCreatePairWithSocketToHost", "NSURLSession", "NSURLConnection",
    "CFHTTPMessageCreateRequest", "nw_connection_create",
]
# Common-word POSIX calls — real, but also ordinary English; lower confidence.
_WEAK_APIS = ["socket", "connect", "bind", "listen", "accept", "recv", "send"]
_STRONG_RE = re.compile(r"\b(" + "|".join(re.escape(a) for a in _STRONG_APIS) + r")\b")
_WEAK_RE = re.compile(r"\b(" + "|".join(re.escape(a) for a in _WEAK_APIS) + r")\b")

# Trivially-uninteresting IPv4 values that are almost never real endpoints.
_TRIVIAL_IPS = {"0.0.0.0", "255.255.255.255", "1.1.1.1", "1.2.3.4", "127.0.0.1"}


def extract_strings(data, min_len=4):
    """Return printable ASCII strings from raw bytes."""
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    return [m.group().decode("latin-1", "ignore") for m in _PRINTABLE.finditer(data)]


def _valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# Characters that mark a C printf/format template or parsing junk rather than a
# real URL/host: %s %d %@ ** {file_id} [%s] etc.
_TEMPLATE_RE = re.compile(r"[%*{}<>\[\]\\^`\s]|%[sdulc@]")


def _is_template(s):
    return bool(_TEMPLATE_RE.search(s))


def analyze_strings(strings):
    """Detect concrete network indicators in a list of strings."""
    found = []
    seen = set()

    def add(idx, value, conf, cat):
        key = (value, cat)
        if key in seen:
            return
        seen.add(key)
        found.append(NetworkEndpoint(idx, value, conf, cat))

    for idx, s in enumerate(strings):
        for m in _URL.finditer(s):
            u = m.group().rstrip(".,);")
            if _is_template(u):     # drop printf templates like http://%s, https://**
                continue
            add(idx, u, 0.95, "URL")
        for m in _IPV4.finditer(s):
            ip = m.group()
            if ip not in _TRIVIAL_IPS and _valid_ip(ip):
                add(idx, ip, 0.70, "IPv4 address")
        for m in _IPV6_CAND.finditer(s):
            cand = m.group()
            if cand.count(":") >= 2 and _valid_ip(cand):
                add(idx, cand, 0.75, "IPv6 address")
        for m in _DOMAIN.finditer(s):
            d = m.group()
            # Real network hostnames in binaries are lowercase; mixed-case or
            # templated matches are parsing junk (e.g. "3.tV", "252Fopen.x.com").
            if not _valid_ip(d) and d == d.lower() and not _is_template(d):
                add(idx, d, 0.55, "Domain")
        for m in _STRONG_RE.finditer(s):
            add(idx, m.group(), 0.85, "Network API")
        for m in _WEAK_RE.finditer(s):
            add(idx, m.group(), 0.45, "Network API (common-word, low confidence)")

    found.sort(key=lambda e: (-e.confidence, e.category, e.content))
    return found


def detect_endpoints(source):
    """Detect endpoints from raw bytes, a list of strings, or a single string."""
    if isinstance(source, (bytes, bytearray)):
        strings = extract_strings(source)
    elif isinstance(source, list):
        # Could be disassembly lines or already-extracted strings — both fine,
        # since we only match concrete indicators, not instruction shapes.
        strings = [str(x) for x in source]
    elif isinstance(source, str):
        strings = source.splitlines()
    else:
        strings = []
    return analyze_strings(strings)


def format_endpoint_results(found: List[NetworkEndpoint], disassembly_lines=None):
    """Grouped, honest report of detected network indicators."""
    if not found:
        return ("No network endpoints detected.\n"
                "(URLs, IP addresses, domains, and network API calls — none found.)")

    from collections import Counter
    by_cat = Counter(e.category for e in found)
    out = ["Network Indicators Detected",
           "=" * 30,
           f"Total: {len(found)}  " + ", ".join(f"{c}: {n}" for c, n in by_cat.items()),
           ""]
    groups = {}
    for e in found:
        groups.setdefault(e.category, []).append(e)

    # Reliable signals first (URLs, IPs, real network APIs), then bare domains last.
    def order(cat):
        if cat == "URL":
            return 0
        if "IP" in cat:
            return 1
        if cat.startswith("Network API") and "low" not in cat:
            return 2
        if cat == "Domain":
            return 9
        return 5

    # Bare domains are demoted and capped — on minified bundles they can include
    # embedded data lists, so they are the least-reliable signal.
    cap = {"Domain": 40}
    for cat in sorted(groups, key=order):
        items = groups[cat]
        limit = cap.get(cat, 200)
        note = ("   (bare domains — may include bundled data; trust URLs/IPs above)"
                if cat == "Domain" else "")
        out.append(f"--- {cat} ({len(items)}){note} ---")
        for e in items[:limit]:
            out.append(f"  {e.content}   (confidence {e.confidence:.2f})")
        if len(items) > limit:
            out.append(f"  ... and {len(items) - limit} more")
        out.append("")
    return "\n".join(out)
