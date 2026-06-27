"""mitmproxy addon: serialize each HTTP(S) flow + extract secrets to a JSONL file.

Loaded by the Network Capture panel via `mitmdump -s mitm_capture_addon.py`.
Writes one JSON object per request/response to the file named by the
RE_CAPTURE_FILE environment variable. The GUI tails that file in real time.
"""

import json
import os
import re
import time

CAPTURE_FILE = os.environ.get("RE_CAPTURE_FILE", "/tmp/re_capture.jsonl")
MAX_BODY = 200_000

# Patterns for the things we want to PROVE we can capture: tokens, API keys, etc.
SECRET_PATTERNS = [
    ("Bearer token", re.compile(r"[Bb]earer\s+([A-Za-z0-9\-._~+/]{8,}=*)")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")),
    ("OAuth/secret param", re.compile(
        r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"auth[_-]?token|x-api-key|password|session[_-]?id)"
        r"\"?\s*[:=]\s*\"?([A-Za-z0-9\-._~+/]{6,}=*)")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]


def extract_secrets(text):
    out = []
    seen = set()
    if not text:
        return out
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0).strip()
            key = (name, val[:160])
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": name, "value": val[:160]})
    return out


def _body(msg):
    if msg is None:
        return ""
    try:
        return msg.get_text(strict=False) or ""
    except Exception:
        try:
            return f"<{len(msg.raw_content or b'')} bytes binary>"
        except Exception:
            return ""


class Capture:
    def response(self, flow):
        try:
            req = flow.request
            resp = flow.response
            req_body = _body(req)[:MAX_BODY]
            resp_body = _body(resp)[:MAX_BODY]
            req_headers = dict(req.headers)
            resp_headers = dict(resp.headers) if resp else {}
            hay = "\n".join([
                req.pretty_url,
                "\n".join(f"{k}: {v}" for k, v in req_headers.items()),
                req_body,
                "\n".join(f"{k}: {v}" for k, v in resp_headers.items()),
                resp_body,
            ])
            rec = {
                "ts": time.time(),
                "method": req.method,
                "url": req.pretty_url,
                "host": req.pretty_host,
                "path": req.path,
                "status": resp.status_code if resp else None,
                "req_headers": req_headers,
                "req_body": req_body,
                "resp_headers": resp_headers,
                "resp_body": resp_body,
                "secrets": extract_secrets(hay),
            }
            with open(CAPTURE_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as e:
            try:
                with open(CAPTURE_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"error": str(e)}) + "\n")
            except Exception:
                pass


addons = [Capture()]
