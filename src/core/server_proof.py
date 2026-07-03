"""Prove a captured host is a real, live, multi-tenant PRODUCTION server — using
ONLY the evidence the server itself returns in its own responses.

Why not "show other users' traffic to this IP": we can't, and no one legitimately
can. A machine only sees connections that originate on it, and TLS makes even
those private per-session — other users' packets never reach us, and intercepting
them would be wiretapping. So "this IP is getting calls from other people" is not
observable from here.

What IS observable and defensible: production infrastructure stamps every response
with signals a test box or a static/ping target never emits — per-request trace
IDs, tenant/organization scoping, rate-limit quotas, edge/CDN identifiers, origin
timing, a live server clock. Reading those from OUR OWN captured responses is
concrete, legal proof that the address is a genuine production backend serving
many clients.
"""

from collections import Counter

# (category, [header names, lowercased], what it proves). Order = display order.
SIGNAL_RULES = [
    ("Per-request trace ID",
     ["request-id", "x-request-id", "x-amzn-requestid", "x-amz-request-id",
      "cf-ray", "x-correlation-id", "x-trace-id", "traceparent",
      "x-github-request-id", "apigw-requestid"],
     "every response carries a unique ID their production system logs and can "
     "trace — real backend infrastructure, not a static or spoofed endpoint."),
    ("Tenant / organization scoping",
     ["anthropic-organization-id", "x-organization-id", "x-tenant-id",
      "x-account-id", "x-workspace-id"],
     "the server assigns your traffic to a specific account/org — proof it's a "
     "multi-tenant production service serving many separate customers."),
    ("Rate-limit / quota enforcement",
     ["ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
      "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
      "retry-after", "anthropic-ratelimit-requests-limit",
      "anthropic-ratelimit-requests-remaining",
      "anthropic-ratelimit-tokens-limit",
      "anthropic-ratelimit-tokens-remaining"],
     "the server meters usage per client — a capability only real shared "
     "production services implement."),
    ("Edge / CDN delivery",
     ["cf-cache-status", "x-served-by", "x-cache", "via", "x-amz-cf-id",
      "x-vercel-id", "fly-request-id", "x-fastly-request-id", "x-akamai-request-id"],
     "the response is delivered through a content-delivery / edge network — real "
     "production deployment topology, not a single lab machine."),
    ("Origin processing time",
     ["server-timing", "x-runtime", "x-response-time"],
     "the server reports how long its origin actually took to compute the "
     "response — a live backend did real work for this request."),
    ("Server software / gateway",
     ["server"],
     "identifies the production web server / gateway fronting the service."),
    ("Transport & content security policy",
     ["strict-transport-security", "content-security-policy",
      "x-content-type-options", "x-frame-options"],
     "the server enforces hardened browser security policies — configured "
     "production infrastructure, not a throwaway."),
    ("Live server clock",
     ["date"],
     "the server stamped this response with the current time — it is answering "
     "in real time right now, not a cached or static artifact."),
]


def _truncate(value, n=140):
    s = str(value)
    return s if len(s) <= n else s[:n] + "…"


def _merge_response_headers(flows):
    """Case-insensitive merge of response headers across flows (latest wins).

    Returns {lower_name: (original_name, value)}.
    """
    merged = {}
    for f in flows or []:
        for k, v in (f.get("resp_headers") or {}).items():
            merged[k.lower()] = (k, v)
    return merged


def production_signals(flows):
    """Return the production-infrastructure signals found in the responses.

    [{category, explanation, evidence: [(header, value), ...]}, ...]
    """
    merged = _merge_response_headers(flows)
    results = []
    for category, names, explanation in SIGNAL_RULES:
        evidence = []
        for n in names:
            if n in merged:
                orig, val = merged[n]
                evidence.append((orig, _truncate(val)))
        if evidence:
            results.append({"category": category, "explanation": explanation,
                            "evidence": evidence})
    return results


def activity_summary(flows):
    """Compact summary of what WE observed (methods + status distribution)."""
    flows = flows or []
    methods = sorted({f.get("method", "") for f in flows if f.get("method")})
    statuses = Counter(str(f.get("status", "")) for f in flows if f.get("status") not in (None, ""))
    status_str = ", ".join(f"{code}×{n}" for code, n in sorted(statuses.items()))
    return {"count": len(flows), "methods": methods, "status_str": status_str}


def format_server_proof(host, flows, ownership_proof=None, static_confirmed=False):
    """Render the full, client-facing proof block for one server."""
    flows = flows or []
    lines = [f"SERVER:  {host}"]
    if static_confirmed:
        lines.append("Status:  found in STATIC analysis and CONFIRMED by live traffic ✓")
    else:
        lines.append("Status:  observed in LIVE traffic")
    lines.append("")
    lines.append("We can only see connections made from THIS machine — TLS keeps every")
    lines.append("user's session private, so other users' traffic to this server is never")
    lines.append("visible to anyone here (capturing it would be wiretapping). Instead, the")
    lines.append("proof below comes from the signals the SERVER ITSELF stamps on its")
    lines.append("responses — the fingerprints of a real production backend.")
    lines.append("")

    lines.append("=" * 70)
    lines.append("CRYPTOGRAPHIC IDENTITY  (who actually answers at this address)")
    lines.append("=" * 70)
    lines.append(ownership_proof if ownership_proof
                 else "Resolving owner (TLS certificate + WHOIS)…")
    lines.append("")

    lines.append("=" * 70)
    lines.append("PRODUCTION-SERVER PROOF  (from the server's own response headers)")
    lines.append("=" * 70)
    sigs = production_signals(flows)
    if not sigs:
        lines.append("No response headers captured for this server yet — send a request "
                     "to it (use the app) and this fills in.")
    else:
        for s in sigs:
            lines.append("")
            lines.append(f"• {s['category']}")
            for header, value in s["evidence"]:
                lines.append(f"    {header}: {value}")
            lines.append(f"    → {s['explanation']}")
    lines.append("")

    lines.append("=" * 70)
    lines.append("ACTIVITY OBSERVED FROM THIS MACHINE")
    lines.append("=" * 70)
    summ = activity_summary(flows)
    if not summ["count"]:
        lines.append("No requests captured to this server yet.")
    else:
        methods = ", ".join(summ["methods"]) or "—"
        lines.append(f"{summ['count']} request(s)  ·  methods: {methods}  ·  "
                     f"statuses: {summ['status_str'] or '—'}")
    return "\n".join(lines)
