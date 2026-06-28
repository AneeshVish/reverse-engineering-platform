"""Known tracker / analytics / attribution domain classification (claim 4 evidence).

A curated list of well-known third-party tracking, analytics, crash-reporting,
attribution, and session-replay services. When an app contacts these — especially
while sending persistent identifiers (see pii_classify) — that is concrete evidence
of user tracking, far stronger than asserting "they track you".

This is a static, offline list (no network); matching is by registrable-domain
suffix so sub-domains (e.g. api.amplitude.com) are caught.
"""

# domain -> category
TRACKERS = {
    # analytics
    "google-analytics.com": "analytics (Google)",
    "googletagmanager.com": "analytics (Google Tag Manager)",
    "analytics.google.com": "analytics (Google)",
    "app-measurement.com": "analytics (Firebase/Google)",
    "firebase-settings.crashlytics.com": "analytics (Firebase)",
    "amplitude.com": "analytics (Amplitude)",
    "mixpanel.com": "analytics (Mixpanel)",
    "segment.io": "analytics (Segment)",
    "segment.com": "analytics (Segment)",
    "mparticle.com": "analytics (mParticle)",
    "flurry.com": "analytics (Flurry)",
    "heapanalytics.com": "analytics (Heap)",
    "omtrdc.net": "analytics (Adobe)",
    "sc.omtrdc.net": "analytics (Adobe)",
    "quantserve.com": "analytics (Quantcast)",
    "scorecardresearch.com": "ad-tracker (Comscore)",
    # ad networks / trackers
    "doubleclick.net": "ad-tracker (Google)",
    "googlesyndication.com": "ad-tracker (Google)",
    "googleadservices.com": "ad-tracker (Google)",
    "amazon-adsystem.com": "ad-tracker (Amazon)",
    "criteo.com": "ad-tracker (Criteo)",
    "demdex.net": "ad-tracker (Adobe)",
    "adnxs.com": "ad-tracker (Xandr)",
    "rubiconproject.com": "ad-tracker (Magnite)",
    "pubmatic.com": "ad-tracker (PubMatic)",
    "taboola.com": "ad-tracker (Taboola)",
    "outbrain.com": "ad-tracker (Outbrain)",
    # social trackers
    "facebook.com": "social-tracker (Meta)",
    "graph.facebook.com": "social-tracker (Meta)",
    "connect.facebook.net": "social-tracker (Meta)",
    "facebook.net": "social-tracker (Meta)",
    "ads-twitter.com": "social-tracker (X/Twitter)",
    "analytics.tiktok.com": "social-tracker (TikTok)",
    "bytedance.com": "analytics (ByteDance)",
    # attribution / MMP
    "adjust.com": "attribution (Adjust)",
    "adjust.io": "attribution (Adjust)",
    "appsflyer.com": "attribution (AppsFlyer)",
    "branch.io": "attribution (Branch)",
    "kochava.com": "attribution (Kochava)",
    "singular.net": "attribution (Singular)",
    "tenjin.com": "attribution (Tenjin)",
    # crash / monitoring / session replay
    "sentry.io": "crash-reporting (Sentry)",
    "crashlytics.com": "crash-reporting (Crashlytics)",
    "bugsnag.com": "crash-reporting (Bugsnag)",
    "instabug.com": "crash-reporting (Instabug)",
    "hotjar.com": "session-replay (Hotjar)",
    "fullstory.com": "session-replay (FullStory)",
    "logrocket.com": "session-replay (LogRocket)",
    "smartlook.com": "session-replay (Smartlook)",
    # consent / data brokers
    "onetrust.com": "consent/tracking (OneTrust)",
    "cookielaw.org": "consent/tracking (OneTrust)",
}


def _registrable(host):
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def classify(host):
    """Return the tracker category for a host, or '' if first-party/unknown."""
    if not host:
        return ""
    h = host.lower().strip(".")
    # Exact or sub-domain match against any known tracker domain.
    for dom, cat in TRACKERS.items():
        if h == dom or h.endswith("." + dom):
            return cat
    return ""


def is_tracker(host):
    return bool(classify(host))


def classify_endpoints(hosts):
    """Map a list of hosts -> {host: category} for the trackers among them."""
    return {h: classify(h) for h in hosts if classify(h)}


def summarize(hosts):
    """Human-readable tracker summary for a set of endpoint hosts."""
    found = classify_endpoints(hosts)
    if not found:
        return "No known third-party trackers among the observed endpoints."
    lines = [f"THIRD-PARTY TRACKERS DETECTED — {len(found)} of {len(set(hosts))} endpoints:"]
    for host, cat in sorted(found.items()):
        lines.append(f"  • {host}  →  {cat}")
    lines.append("")
    lines.append("Contacting these services is evidence of tracking; cross-reference with the "
                 "PII fields sent to them (Network Capture) to show exactly what is shared.")
    return "\n".join(lines)
