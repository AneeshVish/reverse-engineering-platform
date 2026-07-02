"""Evidence-based ranking of detected endpoints.

Static string extraction on a real app (especially a minified Electron bundle)
yields hundreds of "endpoints" that are mostly NOT things the app talks to:
XML/JSON namespace URIs, spec/doc links inside bundled libraries, the code-signing
certificate chain, library default constants, and unit-test fixtures.

This module sorts every detected indicator into evidence tiers so the UI can lead
with what is real and collapse the noise, instead of dumping 300 look-alike lines:

  confirmed-live : host seen in the OS socket table / captured traffic (strongest)
  live-only      : observed live but not found statically (dynamic/obfuscated)
  real-server    : a URL host that resolves and isn't a known doc/namespace host
  local          : loopback / link-local / private / cloud-metadata address
  pki            : certificate-authority infrastructure from the signature chain
  library-ref    : namespace URI, spec/issue/doc link inside a bundled dependency
  test/malformed : example.com, foo.bar, creds/fragment junk, single-label hosts
  unresolved     : a plausible host that did not resolve (weak, unproven)

Only `confirmed-live`, `live-only`, and `real-server` should be presented as
endpoints the application actually uses.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from src.core import tracker_list


# --- Known-noise classification -------------------------------------------

# Registrable hosts (or exact hosts) that are documentation, specification,
# schema-namespace, source-repo, or standards references — never live endpoints
# when they show up inside a bundled JS/library blob.
_DOC_HOST_SUFFIXES = (
    "json-schema.org", "apache.org", "ietf.org",
    "whatwg.org", "tc39.es", "ecma-international.org", "rfc-editor.org",
    "unicode.org", "khronos.org",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "bugs.chromium.org", "issues.chromium.org", "bugs.webkit.org",
    "chromium.org", "webkit.org",
    "msdn.microsoft.com", "docs.microsoft.com", "learn.microsoft.com",
    "developer.mozilla.org", "developer.apple.com", "stackoverflow.com",
    "npmjs.com", "nodejs.org", "python.org", "readthedocs.io",
    "feross.org", "evilmartians.com", "git.new",
    "mit.edu", "stanford.edu",
)

# Namespace-identifier hosts (used as XML/RDF/XMP namespaces, not fetched).
_NAMESPACE_HOST_SUFFIXES = (
    "ns.adobe.com", "purl.org", "xmlns.com", "schema.org",
    "w3.org", "xfa.org",
)

# Apple (and similar) PKI hosts that appear because of the code-signing chain,
# not because the app calls them at runtime.
_PKI_HOST_PATTERNS = (
    re.compile(r"^(certs|ocsp|ocsp2|crl)\.apple\.com$"),
    re.compile(r"^(crl|ocsp)\.", re.IGNORECASE),
    re.compile(r"\.?apple\.com$") ,  # only PKI when path is a CA artifact (handled below)
)

# Obvious placeholder / test-fixture hosts.
_TEST_HOSTS = {
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "foo.bar", "foo.com", "bar.com", "test.com",
    "a.com", "a.b", "b.c", "domain.com", "yourdomain.com",
}


@dataclass
class RankedEndpoint:
    value: str                 # the raw matched string (URL / host / IP)
    host: str                  # normalized bare host (or the IP)
    tier: str                  # one of the tiers documented above
    reason: str                # short human explanation of the classification
    tracker: str = ""          # tracker category, if any
    resolved: List[str] = field(default_factory=list)


# Display order + friendly section titles.
_TIER_ORDER = {
    "confirmed-live": 0,
    "live-only": 1,
    "real-server": 2,
    "local": 3,
    "pki": 4,
    "library-ref": 5,
    "namespace": 6,
    "test/malformed": 7,
    "unresolved": 8,
}
_TIER_TITLE = {
    "confirmed-live": "CONFIRMED LIVE — app is actually talking to these (socket-proven)",
    "live-only": "LIVE-ONLY — observed live, not found in static strings",
    "real-server": "REAL SERVERS — plausible endpoints (resolve; not doc/namespace)",
    "local": "LOCAL / METADATA — loopback, private, or cloud-metadata addresses",
    "pki": "CERTIFICATE INFRASTRUCTURE — from the signing chain, not app behavior",
    "library-ref": "LIBRARY REFERENCES — doc/spec/repo links inside dependencies (informational)",
    "namespace": "NAMESPACE IDENTIFIERS — XML/JSON namespaces, never fetched",
    "test/malformed": "TEST / MALFORMED — placeholders and parser junk",
    "unresolved": "UNRESOLVED — plausible host that did not resolve (unproven)",
}
_REAL_TIERS = ("confirmed-live", "live-only", "real-server")


def host_of(s: str) -> str:
    """Normalize 'https://h/p', 'h:443', 'user@h' -> bare lowercase host/IP."""
    if not s:
        return ""
    s = str(s).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.split("@", 1)[-1]
    # strip a trailing :port for hostnames (leave bare IPv6 literals alone)
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s.lower().strip(".")


def _is_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _local_reason(ip):
    if ip.is_loopback:
        return "loopback address (this machine)"
    if ip.is_link_local:
        # 169.254.169.254 is the well-known cloud-metadata service.
        if str(ip) == "169.254.169.254":
            return "cloud-metadata service (link-local; library default, not a server)"
        return "link-local address (not a routable server)"
    if ip.is_private:
        return "private LAN address (not a public server)"
    if ip.is_unspecified:
        return "unspecified address (0.0.0.0 / ::)"
    if ip.is_reserved or ip.is_multicast:
        return "reserved/multicast address"
    return ""


def _suffix_match(host: str, suffixes) -> bool:
    return any(host == suf or host.endswith("." + suf) for suf in suffixes)


def _classify(value: str, host: str, live_hosts, live_ips, resolved):
    """Return (tier, reason, resolved_ips) for one endpoint value."""
    ips = resolved.get(host, []) if resolved else []

    # 0) Malformed / non-host (single label, non-ascii, empty).
    if not host or "." not in host and _is_ip(host) is None:
        return "test/malformed", "not a resolvable host (single label / junk)", ips
    if any(ord(c) > 127 for c in host):
        return "test/malformed", "non-ASCII host (parser artifact)", ips

    ipobj = _is_ip(host)

    # 1) Local / private / metadata addresses.
    if ipobj is not None:
        lr = _local_reason(ipobj)
        if lr:
            return "local", lr, ips

    # 2) Confirmed by live observation (the strongest signal).
    if host in (live_hosts or set()):
        return "confirmed-live", "seen live in the OS socket table / capture", ips
    if any(ip in (live_ips or set()) for ip in ips):
        return "confirmed-live", "resolves to an IP observed live", ips

    # 3) Placeholder / test hosts.
    if host in _TEST_HOSTS:
        return "test/malformed", "placeholder/test host", ips

    # 4) Certificate-authority infrastructure (signing chain, not app traffic).
    if re.match(r"^(certs|ocsp|ocsp2|crl)\.", host) and host.endswith("apple.com"):
        return "pki", "Apple certificate/OCSP/CRL host (from the signing chain)", ips
    if re.match(r"^(ocsp|crl)\.", host):
        return "pki", "OCSP/CRL certificate-revocation host", ips

    # 5) Namespace identifiers (used as XML/JSON namespaces, never fetched).
    if _suffix_match(host, _NAMESPACE_HOST_SUFFIXES):
        return "namespace", "namespace identifier, not a network call", ips

    # 6) Documentation / spec / repo references inside bundled libraries.
    if _suffix_match(host, _DOC_HOST_SUFFIXES):
        return "library-ref", "doc/spec/repo link inside a dependency", ips

    # 7) A public host that resolves -> a plausible real server.
    if ips and (ipobj is not None or "." in host):
        return "real-server", "resolves to a public server IP", ips
    if ipobj is not None:
        return "real-server", "explicit public IP address", ips

    # 8) Plausible host, but no resolution evidence.
    return "unresolved", "plausible host; did not resolve (unproven)", ips


def rank(endpoints: Sequence,
         live_hosts: Optional[Sequence[str]] = None,
         live_ips: Optional[Sequence[str]] = None,
         resolved: Optional[Dict[str, List[str]]] = None) -> List[RankedEndpoint]:
    """Rank detected endpoints into evidence tiers.

    `endpoints`  : NetworkEndpoint objects (with .content/.category) or raw strings.
    `live_hosts` : hostnames observed live (e.g. PTR names from the socket table).
    `live_ips`   : IPs observed live (from live_connections).
    `resolved`   : {host: [ips]} DNS results (from network_intel.resolve_endpoints).
    """
    live_host_set = {host_of(h) for h in (live_hosts or []) if host_of(h)}
    live_ip_set = {str(x).strip() for x in (live_ips or []) if str(x).strip()}
    resolved = {host_of(k): v for k, v in (resolved or {}).items()}

    seen = set()
    ranked: List[RankedEndpoint] = []

    def consider(value: str):
        host = host_of(value)
        key = (value, host)
        if not host or key in seen:
            return
        seen.add(key)
        tier, reason, ips = _classify(value, host, live_host_set, live_ip_set, resolved)
        ranked.append(RankedEndpoint(
            value=value, host=host, tier=tier, reason=reason,
            tracker=tracker_list.classify(host), resolved=ips))

    # Static indicators. Prefer URLs and IPs; skip the low-confidence bare-domain
    # and common-word "network API" noise the detector already flags.
    for e in endpoints or []:
        content = getattr(e, "content", None)
        category = getattr(e, "category", None)
        if content is None:                     # a raw string
            consider(str(e))
            continue
        if category in ("URL",) or (category and "IP" in category):
            consider(content)
        elif category == "Domain":
            # keep domains only so they can be de-noised, not featured
            consider(content)

    # Live-only hosts/IPs that never appeared statically.
    for h in live_host_set | live_ip_set:
        if not any(r.host == h for r in ranked):
            ipobj = _is_ip(h)
            lr = _local_reason(ipobj) if ipobj is not None else ""
            if lr:
                ranked.append(RankedEndpoint(h, h, "local", lr,
                                             tracker_list.classify(h)))
            else:
                ranked.append(RankedEndpoint(
                    h, h, "live-only", "observed live; not in static strings",
                    tracker_list.classify(h)))

    # A single host often appears as both a "URL" and a "Domain" indicator; collapse
    # to one entry per host, keeping the strongest tier (and any resolved IPs).
    best: Dict[str, RankedEndpoint] = {}
    for r in ranked:
        cur = best.get(r.host)
        if cur is None or _TIER_ORDER.get(r.tier, 99) < _TIER_ORDER.get(cur.tier, 99):
            if cur is not None and not r.resolved and cur.resolved:
                r.resolved = cur.resolved
            best[r.host] = r
        elif not cur.resolved and r.resolved:
            cur.resolved = r.resolved

    deduped = list(best.values())
    deduped.sort(key=lambda r: (_TIER_ORDER.get(r.tier, 99), r.host))
    return deduped


def summarize_counts(ranked: Sequence[RankedEndpoint]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in ranked:
        counts[r.tier] = counts.get(r.tier, 0) + 1
    return counts


def format_ranked(ranked: Sequence[RankedEndpoint], noise_preview: int = 8) -> str:
    """Grouped, evidence-first report. Real tiers listed in full; noise collapsed."""
    if not ranked:
        return "No network endpoints detected."

    counts = summarize_counts(ranked)
    real = sum(counts.get(t, 0) for t in _REAL_TIERS)
    trackers = sum(1 for r in ranked if r.tracker)
    out = [
        "ENDPOINT INTELLIGENCE — ranked by evidence",
        "=" * 44,
        f"{len(ranked)} indicators total · {real} are real/observed endpoints · "
        f"{trackers} known trackers.",
        "Only the top sections are endpoints the app actually uses; the rest are "
        "library strings, namespaces, and the signing chain.",
        "",
    ]

    groups: Dict[str, List[RankedEndpoint]] = {}
    for r in ranked:
        groups.setdefault(r.tier, []).append(r)

    for tier in sorted(groups, key=lambda t: _TIER_ORDER.get(t, 99)):
        items = groups[tier]
        out.append(f"--- {_TIER_TITLE.get(tier, tier)}  ({len(items)}) ---")
        # Real/actionable tiers are shown in full; noise tiers are previewed.
        full = tier in _REAL_TIERS or tier in ("local", "pki")
        limit = len(items) if full else noise_preview
        for r in items[:limit]:
            line = f"  {r.host}"
            if r.resolved and tier in _REAL_TIERS:
                line += f"  ->  {', '.join(r.resolved[:3])}"
            if r.tracker:
                line += f"   [{r.tracker}]"
            line += f"   ({r.reason})"
            out.append(line)
        if limit < len(items):
            out.append(f"  … and {len(items) - limit} more (collapsed as noise)")
        out.append("")

    return "\n".join(out)
