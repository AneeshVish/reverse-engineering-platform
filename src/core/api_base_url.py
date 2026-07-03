"""Pick the best API base URL for Access Path probes — from capture, live sockets, static intel.

Prefers authenticated POST/JSON/SSE API calls over static assets, trackers, and
bundled-library noise (Microsoft Graph doc links, Apple PKI, etc.).
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from src.core import endpoint_rank, tracker_list

# High-value primary API routes (chat, inference).
_PRIMARY_API = re.compile(
    r"/(?:messages|completion|completions|chat_conversations|chat/|generate|predict)(?:/|$)",
    re.I,
)
# Session-scoped / plugin / MCP paths — not valid probe bases.
_EPHEMERAL_PATH = re.compile(
    r"/(?:mcp|toolbox|shttp|websocket|ws/|socket\.io|subscribe|events/|stream/)[/]|"
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)",
    re.I,
)
_UUID_IN_PATH = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)
# Feature/integration routes — real traffic but wrong probe base (GitHub sync, MCP, etc.).
_FEATURE_PATH = re.compile(
    r"/(?:code|github|gitlab|integrations|oauth|settings|preferences|toolbox|mcp|shttp|"
    r"batch-|upload|download|telemetry|analytics|rum|assets|static)(?:/|$)|"
    r"/v1/(?:code|toolbox|integrations)/",
    re.I,
)
# High-value API path segments (chat, inference, CRUD APIs).
_API_PATH = re.compile(
    r"/(?:api|v\d+|graphql|rest)(?:/|$)|"
    r"/(?:messages|completion|completions|chat|generate|predict|query|invoke|stream|conversations)",
    re.I,
)
_STATIC_ASSET = re.compile(r"\.(?:js|css|png|jpe?g|svg|woff2?|ico|map|gif|webp|ttf|eot)(?:\?|$)", re.I)
_NOISE_PATHS = frozenset({
    "/favicon.ico", "/robots.txt", "/ping", "/health", "/healthz", "/ready", "/live",
    "/metrics", "/.well-known/", "/manifest.json",
})

# When live sockets prove vendor org but pinning hides hostnames, use these API roots.
_VENDOR_CANONICAL = {
    "anthropic": [
        "https://api.anthropic.com/v1/messages",
        "https://claude.ai/api/organizations/org/chat_conversations/conv/completion",
        "https://claude.ai",
    ],
    "openai": [
        "https://api.openai.com/v1/chat/completions",
        "https://api.openai.com/v1/responses",
    ],
    "spotify": ["https://api.spotify.com/v1/me"],
    "discord": ["https://discord.com/api/v9/channels"],
}

# Bundled SDK hosts — not the app's primary API unless seen in captured flows.
_BUNDLED_SDK_HOSTS = (
    "graph.microsoft.com", "login.microsoftonline.com", "login.microsoftonline.us",
    "login.chinacloudapi.cn", "ciamlogin.com",
)


@dataclass
class BaseUrlSuggestion:
    url: str
    score: float
    source: str          # capture | live_socket | static_intel | canonical
    reason: str

    def beats(self, other: Optional["BaseUrlSuggestion"], margin: float = 15.0) -> bool:
        if other is None:
            return True
        return self.score >= other.score + margin


def _vendor_from_app(app_name: str) -> str:
    n = (app_name or "").lower().replace(".app", "")
    if "claude" in n or "anthropic" in n:
        return "anthropic"
    if "chatgpt" in n or "openai" in n:
        return "openai"
    if "spotify" in n:
        return "spotify"
    if "discord" in n:
        return "discord"
    return ""


def _vendor_from_org(org: str) -> str:
    o = (org or "").lower()
    if "anthropic" in o:
        return "anthropic"
    if "openai" in o:
        return "openai"
    if "spotify" in o:
        return "spotify"
    if "discord" in o:
        return "discord"
    return ""


def is_ephemeral_url(url: str) -> bool:
    """True for session IDs, MCP/toolbox routes, and other non-reusable probe targets."""
    return not is_probe_suitable_url(url) if url else True


def is_probe_suitable_url(url: str) -> bool:
    """True only for core API roots suitable for controlled probes."""
    if not url:
        return False
    parsed = urlparse(url if "://" in url else "https://" + url)
    path = parsed.path or "/"
    pl = path.lower()
    host = (parsed.hostname or "").lower()

    if _EPHEMERAL_PATH.search(pl) or _UUID_IN_PATH.search(path):
        return False
    if "/toolbox/" in pl or "/shttp/" in pl:
        return False
    if _FEATURE_PATH.search(pl):
        return False

    if _PRIMARY_API.search(pl):
        return True
    if host == "api.anthropic.com" and pl.startswith("/v1/messages"):
        return True
    if host.endswith("claude.ai") and "/api/" in pl and _PRIMARY_API.search(pl):
        return True
    if host.endswith("openai.com") and "/v1/chat/completions" in pl:
        return True
    return False


def normalize_probe_url(url: str, app_name: str = "") -> str:
    """Map captured URLs to a stable API root suitable for probes."""
    if is_probe_suitable_url(url):
        return url
    vendor = _vendor_from_app(app_name)
    canon = _canonical_for_vendor(vendor, {})
    if canon:
        return canon.url
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname or ""
    parts = [p for p in (parsed.path or "/").split("/") if p]
    stable_parts = []
    for p in parts:
        if _UUID_IN_PATH.search("/" + p) or p.lower() in ("mcp", "toolbox", "shttp"):
            break
        stable_parts.append(p)
        if p in ("api", "v1", "v2") and len(stable_parts) >= 2:
            break
    path = "/" + "/".join(stable_parts) if stable_parts else "/"
    return f"https://{host}{path}".rstrip("/") or url


def finalize_suggestion(suggestion: BaseUrlSuggestion, app_name: str) -> BaseUrlSuggestion:
    """Ensure the suggested URL is a stable probe target."""
    if is_probe_suitable_url(suggestion.url):
        return suggestion
    stable = normalize_probe_url(suggestion.url, app_name)
    short = suggestion.url[:70] + ("…" if len(suggestion.url) > 70 else "")
    return BaseUrlSuggestion(
        url=stable,
        score=suggestion.score,
        source=suggestion.source,
        reason=f"Stable API root for probes (ignored feature route {short})",
    )


def is_noise_host(host: str) -> bool:
    """True for trackers, library refs, PKI, and bundled SDK noise."""
    if not host:
        return True
    if tracker_list.classify(host):
        return True
    h = endpoint_rank.host_of(host)
    if h in endpoint_rank._TEST_HOSTS:
        return True
    if endpoint_rank._suffix_match(h, endpoint_rank._DOC_HOST_SUFFIXES):
        return True
    if endpoint_rank._suffix_match(h, endpoint_rank._NAMESPACE_HOST_SUFFIXES):
        return True
    if any(h == sdk or h.endswith("." + sdk) for sdk in _BUNDLED_SDK_HOSTS):
        return True
    if h.endswith(".apple.com") and re.match(r"^(certs|ocsp|crl|www)\.", h):
        return True
    if "googleusercontent.com" in h or h.endswith(".1e100.net"):
        return True
    if "datadoghq.com" in h:
        return True
    return False


def _flow_url(flow: Dict[str, Any]) -> str:
    url = (flow.get("url") or "").strip()
    if url.startswith("http"):
        return url.split("?", 1)[0]
    host = flow.get("host") or ""
    path = flow.get("path") or "/"
    if not host:
        return ""
    scheme = "https" if flow.get("scheme") != "http" else "http"
    return f"{scheme}://{host}{path}"


def _score_flow(flow: Dict[str, Any]) -> float:
    host = flow.get("host") or ""
    if is_noise_host(host):
        return -1000.0

    path = (flow.get("path") or "").lower()
    full = f"https://{host}{path}"
    if not is_probe_suitable_url(full):
        return -300.0
    if _STATIC_ASSET.search(path):
        return -200.0
    if any(path == n or path.startswith(n) for n in _NOISE_PATHS if n.endswith("/")):
        return -150.0
    if path in _NOISE_PATHS:
        return -150.0

    score = 0.0
    method = (flow.get("method") or "GET").upper()
    if method == "POST":
        score += 55
    elif method in ("PUT", "PATCH"):
        score += 35
    elif method == "GET":
        score += 8

    if _API_PATH.search(path):
        score += 45
    if _PRIMARY_API.search(path):
        score += 90

    req_h = {k.lower(): v for k, v in (flow.get("req_headers") or {}).items()}
    resp_h = {k.lower(): v for k, v in (flow.get("resp_headers") or {}).items()}
    ct = (req_h.get("content-type") or resp_h.get("content-type") or "").lower()
    if "application/json" in ct:
        score += 35
    if "event-stream" in ct or "text/event-stream" in ct:
        score += 50

    body = flow.get("req_body") or ""
    if body and len(str(body)) > 20:
        score += 15
    if flow.get("secrets"):
        score += 30

    try:
        from src.core import streaming_capture
        if streaming_capture.is_sse(flow):
            score += 45
    except Exception:
        pass

    if flow.get("ttft_ms"):
        score += 25

    # Deprioritize bare GETs to non-API paths (fonts, config dumps).
    if method == "GET" and not _API_PATH.search(path):
        score -= 35

    status = int(flow.get("status") or 0)
    if 200 <= status < 300:
        score += 10
    elif status >= 400:
        score -= 5

    return score


def _score_static_url(url: str, *, vendor: str, in_live: bool) -> float:
    host = endpoint_rank.host_of(url)
    if is_noise_host(host):
        return -1000.0
    path = urlparse(url if "://" in url else "https://" + url).path or "/"
    score = 20.0
    if in_live:
        score += 40
    if _API_PATH.search(path):
        score += 35
    if vendor and vendor in host:
        score += 25
    if "anthropic" in host or "claude" in host:
        if vendor == "anthropic":
            score += 40
    return score


def _canonical_for_vendor(vendor: str, intel: Dict[str, Any]) -> Optional[BaseUrlSuggestion]:
    if not vendor:
        return None
    hints = _VENDOR_CANONICAL.get(vendor, [])
    if not hints:
        return None
    hosts = {endpoint_rank.host_of(h) for h in (intel.get("hosts") or [])}
    endpoints = " ".join(intel.get("endpoints") or [])
    best_url, best_score = "", -1.0
    for url in hints:
        host = endpoint_rank.host_of(url)
        score = 25.0 + hints.index(url) * -2  # prefer first (most specific API)
        if host in hosts or host in endpoints:
            score += 35
        if _API_PATH.search(urlparse(url).path):
            score += 20
        if score > best_score:
            best_score, best_url = score, url
    if not best_url:
        return None
    return BaseUrlSuggestion(
        url=best_url,
        score=best_score,
        source="canonical",
        reason=f"Live traffic matches {vendor} — using known API root",
    )


def _from_flows(flows: Sequence[Dict[str, Any]], app_name: str = "") -> Optional[BaseUrlSuggestion]:
    best_url, best_score = "", -9999.0
    best_stable_url, best_stable_score = "", -9999.0
    for f in flows or []:
        url = _flow_url(f)
        if not url:
            continue
        sc = _score_flow(f)
        if sc > best_score:
            best_score, best_url = sc, url
        if not is_ephemeral_url(url) and sc > best_stable_score:
            best_stable_score, best_stable_url = sc, url

    pick_url, pick_score = best_url, best_score
    if best_stable_url and (is_ephemeral_url(best_url) or best_stable_score >= best_score - 40):
        pick_url, pick_score = best_stable_url, best_stable_score

    if pick_url and pick_score > 0:
        normalized = normalize_probe_url(pick_url, app_name)
        method = next((f.get("method", "") for f in flows if _flow_url(f) == pick_url), "POST")
        host = endpoint_rank.host_of(normalized)
        reason = f"Best captured {method} to {host}"
        if normalized != pick_url:
            reason = f"Stable API root (ignored feature route {pick_url[:60]}…)"
        elif _PRIMARY_API.search(urlparse(pick_url).path):
            reason += " — primary chat/API route"
        else:
            reason += " (API/JSON/SSE ranked above noise)"
        return finalize_suggestion(BaseUrlSuggestion(
            url=normalized,
            score=pick_score + 100,
            source="capture",
            reason=reason,
        ), app_name)
    # Captured traffic exists but only feature routes (GitHub sync, MCP, etc.).
    if flows:
        vendor = _vendor_from_app(app_name)
        canon = _canonical_for_vendor(vendor, {})
        if canon:
            return finalize_suggestion(BaseUrlSuggestion(
                url=canon.url,
                score=85,
                source="capture",
                reason="Capture shows feature routes only — using stable API root for probes",
            ), app_name)
    return None


def _from_live(live_conns: Sequence[Dict], app_name: str,
               intel: Dict[str, Any]) -> Optional[BaseUrlSuggestion]:
    vendor = _vendor_from_app(app_name)
    org_counts: Dict[str, int] = {}
    org_ips: Dict[str, List[str]] = {}
    for c in live_conns or []:
        org = (c.get("org") or "").strip()
        ip = (c.get("raddr") or "").rsplit(":", 1)[0]
        if not org and c.get("rdns"):
            org = c["rdns"]
        v = _vendor_from_org(org) or vendor
        if not v:
            continue
        org_counts[v] = org_counts.get(v, 0) + 1
        org_ips.setdefault(v, []).append(ip)

    if not org_counts:
        return None

    # Prefer the app's vendor over incidental GCP/CDN sockets.
    primary = vendor if vendor in org_counts else max(org_counts, key=org_counts.get)
    if primary:
        canon = _canonical_for_vendor(primary, intel)
        if canon:
            canon.score += 60 + org_counts.get(primary, 0) * 5
            canon.source = "live_socket"
            ips = org_ips.get(primary, [])[:2]
            canon.reason = (
                f"Live socket to {primary} ({', '.join(ips) or 'connected'}) — "
                f"API root inferred")
            return canon
    return None


def _from_static(intel: Dict[str, Any], endpoints: Sequence,
                 live_hosts: Sequence[str], live_ips: Sequence[str]) -> Optional[BaseUrlSuggestion]:
    vendor = _vendor_from_app(intel.get("path", ""))
    live_host_set = {endpoint_rank.host_of(h) for h in (live_hosts or [])}
    live_ip_set = set(live_ips or [])

    best: Optional[BaseUrlSuggestion] = None
    candidates: List[str] = []
    for ep in intel.get("endpoints") or []:
        if isinstance(ep, str) and ep.startswith("http"):
            candidates.append(ep.split("?", 1)[0])

    for item in endpoints or []:
        raw = getattr(item, "content", None) or str(item)
        if raw.startswith("http"):
            candidates.append(raw.split("?", 1)[0])

    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        host = endpoint_rank.host_of(url)
        in_live = host in live_host_set
        sc = _score_static_url(url, vendor=vendor, in_live=in_live)
        if sc <= 0:
            continue
        if sc > (best.score if best else -9999):
            best = BaseUrlSuggestion(
                url=url,
                score=sc + 30,
                source="static_intel",
                reason=f"Static API URL in app bundle{f' (host seen live)' if in_live else ''}",
            )
    return best


def suggest(*,
            flows: Optional[Sequence[Dict[str, Any]]] = None,
            live_conns: Optional[Sequence[Dict]] = None,
            architecture_intel: Optional[Dict[str, Any]] = None,
            app_name: str = "",
            static_endpoints: Optional[Sequence] = None,
            live_hosts: Optional[Sequence[str]] = None,
            live_ips: Optional[Sequence[str]] = None) -> Optional[BaseUrlSuggestion]:
    """Return the single best base URL for Access Path, or None."""
    intel = architecture_intel or {}
    if app_name and not intel.get("path"):
        intel = {**intel, "path": app_name}

    candidates: List[BaseUrlSuggestion] = []
    cap = _from_flows(flows or [], app_name)
    if cap:
        candidates.append(cap)

    live = _from_live(live_conns or [], app_name, intel)
    if live:
        candidates.append(live)

    stat = _from_static(intel, static_endpoints or [], live_hosts or [], live_ips or [])
    if stat:
        candidates.append(stat)

    if not candidates:
        vendor = _vendor_from_app(app_name)
        canon = _canonical_for_vendor(vendor, intel)
        if canon:
            candidates.append(canon)

    if not candidates:
        return None

    best = max(candidates, key=lambda s: s.score)
    return finalize_suggestion(best, app_name)
