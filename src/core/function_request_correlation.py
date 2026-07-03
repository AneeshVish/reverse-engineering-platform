"""Function→network correlation — match Frida hooks to mitm flows."""

import time
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple

# Frida JS agent snippet for Electron/network hooks (injected alongside runtime_crypto)
NETWORK_HOOK_JS = """
(function() {
    function sendNet(api, url, method, stack) {
        send({ type: 'net_hook', api: api, url: url, method: method || 'GET',
               stack: (stack || '').slice(0, 500), ts: Date.now() });
    }
    // fetch
    if (typeof fetch !== 'undefined') {
        var _fetch = fetch;
        fetch = function(input, init) {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            var method = (init && init.method) || 'GET';
            sendNet('fetch', url, method, new Error().stack);
            return _fetch.apply(this, arguments);
        };
    }
    // XMLHttpRequest
    if (typeof XMLHttpRequest !== 'undefined') {
        var _open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
            this._reUrl = url; this._reMethod = method;
            return _open.apply(this, arguments);
        };
        var _send = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function() {
            sendNet('XMLHttpRequest', this._reUrl || '', this._reMethod || 'GET',
                    new Error().stack);
            return _send.apply(this, arguments);
        };
    }
})();
"""


@dataclass
class NetHookEvent:
    ts: float
    api: str
    url: str
    method: str
    stack: str = ""


def parse_frida_event(event: Dict) -> Optional[Dict]:
    """Normalize a Frida net_hook event."""
    if event.get("type") != "net_hook" and event.get("api") not in (
            "fetch", "XMLHttpRequest", "undici", "SSL_write"):
        payload = event.get("payload") or event
        if isinstance(payload, dict) and payload.get("type") == "net_hook":
            event = payload
        else:
            return None
    url = event.get("url", "")
    if not url and event.get("api") == "SSL_write":
        url = "(tls-plaintext)"
    return {
        "ts": event.get("ts", time.time()),
        "api": event.get("api", ""),
        "url": url,
        "method": event.get("method", ""),
        "stack": event.get("stack", ""),
    }


def _host_path(url: str) -> Tuple[str, str]:
    if not url or url.startswith("("):
        return "", ""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return p.hostname or "", p.path or "/"
    except Exception:
        return "", ""


def correlate(hook_events: List[Dict], flows: List[Dict],
              window_sec: float = 2.0) -> List[Dict]:
    """Match hook events to captured flows by host+path+time."""
    correlations = []
    parsed_hooks = [parse_frida_event(e) for e in hook_events]
    parsed_hooks = [h for h in parsed_hooks if h]

    for hook in parsed_hooks:
        h_host, h_path = _host_path(hook["url"])
        best = None
        best_delta = window_sec + 1
        for f in flows or []:
            f_host = f.get("host", "")
            f_path = f.get("path", "") or "/"
            if h_host and f_host and h_host.lower() != f_host.lower():
                continue
            if h_path and f_path and not f_path.startswith(h_path.rstrip("/")[:20]):
                if h_path not in f.get("url", ""):
                    continue
            fts = f.get("ts", 0)
            delta = abs(hook["ts"] - fts) if fts else 0
            if delta < best_delta:
                best_delta = delta
                best = f
        correlations.append({
            "hook": hook,
            "flow": best,
            "delta_sec": round(best_delta, 3) if best else None,
            "matched": best is not None and best_delta <= window_sec,
        })
    return correlations


def format_report(correlations: List[Dict]) -> str:
    lines = ["FUNCTION → REQUEST CORRELATION", "=" * 60]
    matched = sum(1 for c in correlations if c.get("matched"))
    lines.append(f"Hook events: {len(correlations)}  Matched to flows: {matched}")
    for c in correlations[:25]:
        h = c["hook"]
        lines.append(f"\n  [{h['api']}] {h['method']} {h['url'][:80]}")
        if c.get("matched") and c.get("flow"):
            f = c["flow"]
            lines.append(f"    → {f.get('method', '')} {f.get('host', '')}{f.get('path', '')} "
                           f"({c.get('delta_sec')}s)")
        else:
            lines.append("    → (no matching flow)")
        if h.get("stack"):
            stack_line = h["stack"].split("\n")[1] if "\n" in h["stack"] else h["stack"][:60]
            lines.append(f"    stack: {stack_line.strip()[:80]}")
    return "\n".join(lines)
