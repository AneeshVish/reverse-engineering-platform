"""UI event capture — Electron/desktop user action hooks."""

import time
from typing import Dict, List, Any, Optional

# Frida JS to hook common UI events in Electron renderer
UI_HOOK_JS = """
(function() {
    function sendUI(action, target, detail) {
        send({ type: 'ui_event', action: action, target: target || '',
               detail: (detail || '').slice(0, 200), ts: Date.now() });
    }
    document.addEventListener('click', function(e) {
        var t = e.target;
        var label = (t && (t.id || t.className || t.tagName || '')) + '';
        if (t && t.textContent) label += ':' + t.textContent.slice(0, 40);
        sendUI('click', label.trim(), window.location.href);
    }, true);
    document.addEventListener('submit', function(e) {
        sendUI('submit', (e.target && e.target.action) || 'form', '');
    }, true);
    // Keyboard shortcuts (Send often = Enter in textarea)
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
            sendUI('keydown', 'Enter+Mod (likely send)', '');
        }
    }, true);
})();
"""


def parse_ui_event(event: Dict) -> Optional[Dict]:
    payload = event
    if event.get("type") != "ui_event":
        payload = event.get("payload") or event
    if not isinstance(payload, dict) or payload.get("type") != "ui_event":
        return None
    return {
        "ts": payload.get("ts", time.time()),
        "action": payload.get("action", "unknown"),
        "target": payload.get("target", ""),
        "detail": payload.get("detail", ""),
    }


def format_events(events: List[Dict]) -> str:
    lines = ["UI EVENT CAPTURE", "=" * 60]
    parsed = [parse_ui_event(e) for e in events]
    parsed = [p for p in parsed if p]
    if not parsed:
        return lines[0] + "\n" + "=" * 60 + "\nNo UI events captured. Enable UI hooks in Runtime Crypto."
    for p in parsed[:30]:
        lines.append(f"  [{p['action']}] {p['target']}")
        if p.get("detail"):
            lines.append(f"      {p['detail'][:80]}")
    return "\n".join(lines)
