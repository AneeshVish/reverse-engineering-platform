"""HTTPS client for probes — uses requests + certifi (fixes macOS Python SSL errors)."""

from typing import Any, Dict, Optional


def http_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 body: Optional[bytes] = None, timeout: float = 12.0) -> Dict[str, Any]:
    """Perform an HTTPS request. Returns {status, headers, body, error}."""
    import requests
    hdrs = dict(headers or {})
    try:
        resp = requests.request(
            method.upper(),
            url,
            headers=hdrs,
            data=body,
            timeout=timeout,
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": (resp.text or "")[:8000],
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        err = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in err.upper() or "certificate verify failed" in err.lower():
            err += " — run: .venv/bin/pip install certifi (or use Install Certificates.command for Python)"
        return {"status": 0, "headers": {}, "body": "", "error": err}
