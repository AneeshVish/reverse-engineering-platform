"""Behavior timeline — user action → function → request → SSE → UI update."""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class TimelineEvent:
    ts: float
    kind: str          # ui_action | function_call | network_request | sse_token | ui_update | telemetry
    label: str
    detail: str = ""
    host: str = ""
    path: str = ""
    linked_id: str = ""


class BehaviorTimeline:
    def __init__(self):
        self.events: List[TimelineEvent] = []

    def add(self, kind: str, label: str, detail: str = "", **kwargs):
        self.events.append(TimelineEvent(
            ts=kwargs.get("ts", time.time()),
            kind=kind, label=label, detail=detail,
            host=kwargs.get("host", ""), path=kwargs.get("path", ""),
            linked_id=kwargs.get("linked_id", ""),
        ))

    def add_ui_action(self, action: str, detail: str = ""):
        self.add("ui_action", action, detail)

    def add_function_call(self, func: str, url: str = ""):
        self.add("function_call", func, url)

    def add_network(self, method: str, host: str, path: str, status: str = ""):
        self.add("network_request", f"{method} {path}", status, host=host, path=path)

    def add_sse(self, token_preview: str, host: str = "", path: str = ""):
        self.add("sse_token", "token", token_preview[:60], host=host, path=path)

    def add_telemetry(self, vendor: str, session_id: str = ""):
        self.add("telemetry", vendor, session_id)

    def merge_flows(self, flows: List[Dict]):
        for f in flows or []:
            self.add_network(
                f.get("method", "?"), f.get("host", ""), f.get("path", ""),
                str(f.get("status", "")),
            )
            from src.core import streaming_capture as sc
            if sc.is_sse(f):
                for tok in sc.extract_sse_tokens(f.get("resp_body") or "")[:5]:
                    self.add_sse(tok, f.get("host", ""), f.get("path", ""))

    def merge_frida_events(self, events: List[Dict]):
        for e in events or []:
            api = e.get("api", "")
            op = e.get("op", "")
            if op in ("tls-send", "tls-recv") or api in ("fetch", "XMLHttpRequest", "undici"):
                self.add_function_call(api or op, str(e.get("data", ""))[:80])

    def merge_ui_events(self, events: List[Dict]):
        for e in events or []:
            self.add_ui_action(e.get("action", "click"), e.get("target", ""))

    def sorted_events(self) -> List[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.ts)

    def format_report(self) -> str:
        evs = self.sorted_events()
        if not evs:
            return ("No timeline events yet.\n"
                    "Capture traffic + enable Runtime Crypto / UI hooks to build the chain.")
        lines = ["BEHAVIOR TIMELINE", "=" * 60]
        icons = {
            "ui_action": "👆", "function_call": "⚙", "network_request": "→",
            "sse_token": "◆", "ui_update": "✓", "telemetry": "📊",
        }
        for e in evs:
            icon = icons.get(e.kind, "•")
            loc = f" {e.host}{e.path}" if e.host else ""
            lines.append(f"{icon} [{e.kind}] {e.label}{loc}")
            if e.detail:
                lines.append(f"      {e.detail[:100]}")
        return "\n".join(lines)


_timeline: Optional[BehaviorTimeline] = None


def session_timeline() -> BehaviorTimeline:
    global _timeline
    if _timeline is None:
        _timeline = BehaviorTimeline()
    return _timeline
