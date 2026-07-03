"""Engagement report generation — HTML export for client delivery."""

import html
import time
from typing import Dict, List, Any, Optional

from src.core.evidence_store import session_store
from src.core.target_profile import session_profile
from src.core.engagement_scope import engagement_manager


def generate_html(*, flows=None, behavior_infer_text="", access_path_text="",
                  timeline_text="", metrics_text="", probe_results=None) -> str:
    store = session_store()
    profile = session_profile()
    mgr = engagement_manager()
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

    sections = []

    sections.append(f"""<section><h2>Engagement Summary</h2>
    <p>Client: {html.escape(mgr.scope.client or 'N/A')}</p>
    <p>Target: {html.escape(profile.name or profile.path or 'N/A')}</p>
    <p>Generated: {ts}</p>
    <p>Flows captured: {len(flows or [])}</p></section>""")

    ev_text = store.format_report(flows=flows, probe_results=probe_results)
    sections.append(f"<section><h2>Evidence Chain</h2><pre>{html.escape(ev_text)}</pre></section>")

    if behavior_infer_text:
        sections.append(f"<section><h2>Behavior Inference (L3)</h2><pre>{html.escape(behavior_infer_text)}</pre></section>")
    if timeline_text:
        sections.append(f"<section><h2>Behavior Timeline (L2)</h2><pre>{html.escape(timeline_text)}</pre></section>")
    if metrics_text:
        sections.append(f"<section><h2>Behavior Metrics</h2><pre>{html.escape(metrics_text)}</pre></section>")
    if access_path_text:
        sections.append(f"<section><h2>Access Paths</h2><pre>{html.escape(access_path_text)}</pre></section>")

    sections.append(f"""<section><h2>Cannot Be Determined</h2>
    <ul>
    <li>Exact database product on happy-path 200 responses alone</li>
    <li>Number of internal microservices</li>
    <li>Cross-cluster forwarding without converging evidence</li>
    <li>Server-side business logic internals</li>
    </ul></section>""")

    audit = mgr.export_audit()
    sections.append(f"<section><h2>Audit Log</h2><pre>{html.escape(audit)}</pre></section>")

    body = "\n".join(sections)
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>RED TEAM Engagement Report</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; }}
h1 {{ border-bottom: 2px solid #333; }}
pre {{ background: #f4f4f4; padding: 1em; overflow-x: auto; white-space: pre-wrap; }}
section {{ margin: 2em 0; }}
</style></head>
<body><h1>RED TEAM Engagement Report</h1>
{body}
</body></html>"""


def save_report(path: str, **kwargs):
    content = generate_html(**kwargs)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
