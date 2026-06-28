"""Correlate statically-extracted endpoints with live-observed connections.

A hostname embedded in a binary is only a CLAIM that the app uses that endpoint —
anyone can pull strings. When the same host appears as a live socket or a captured
request, that MATCH is the proof the static finding is real and actually used.

This joins the two sets and tags each endpoint:
  - confirmed       : found statically AND seen live  (the strong proof)
  - predicted-only  : found in the binary, not seen live yet
  - live-only       : observed live but not found statically (dynamic/obfuscated)
"""

from src.core import tracker_list


def host_of(s):
    """Normalize 'https://h/p', 'h:443', 'h' -> bare lowercase host."""
    if not s:
        return ""
    s = str(s).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop path
    s = s.split("@", 1)[-1]         # drop creds
    # strip :port (but keep bare IPv6 untouched — rare here)
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s.lower().strip(".")


def correlate(static_hosts, live_hosts):
    """Return sorted rows: [{host, status, tracker}]."""
    static = {host_of(s) for s in (static_hosts or []) if host_of(s)}
    live = {host_of(s) for s in (live_hosts or []) if host_of(s)}
    rows = []
    for h in sorted(static | live):
        if h in static and h in live:
            status = "confirmed"
        elif h in static:
            status = "predicted-only"
        else:
            status = "live-only"
        rows.append({"host": h, "status": status, "tracker": tracker_list.classify(h)})
    # confirmed first, then predicted, then live-only
    order = {"confirmed": 0, "predicted-only": 1, "live-only": 2}
    rows.sort(key=lambda r: (order.get(r["status"], 9), r["host"]))
    return rows


def format_correlation(rows):
    if not rows:
        return "No endpoints to correlate."
    confirmed = sum(1 for r in rows if r["status"] == "confirmed")
    trackers = sum(1 for r in rows if r["tracker"])
    lines = ["STATIC ↔ LIVE ENDPOINT CORRELATION",
             f"  {confirmed}/{len(rows)} endpoints CONFIRMED (found in binary AND seen live); "
             f"{trackers} are known trackers.", ""]
    tag = {"confirmed": "✓ CONFIRMED   ", "predicted-only": "· predicted    ",
           "live-only": "! live-only    "}
    for r in rows:
        line = f"  {tag.get(r['status'], r['status'])} {r['host']}"
        if r["tracker"]:
            line += f"   [{r['tracker']}]"
        lines.append(line)
    lines.append("")
    lines.append("A CONFIRMED endpoint is proof the static finding is real — the app actually "
                 "connects there. Pair with the ownership proof-card and captured payloads.")
    return "\n".join(lines)
