"""Engagement scope and Rules of Engagement — gates all active RED TEAM actions.

Set SCOPE_GATE_ENABLED = True when client-signed RoE scope files are required again.
"""

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

# Internal dev: probes/validation run without loading a signed scope file.
# Re-enable before client engagements.
SCOPE_GATE_ENABLED = False


ALLOWED_ACTIONS = frozenset([
    "passive_capture",
    "controlled_probe",
    "credential_replay",
    "staging_access",
    "region_probe",
    "active_scan",
])

ROE_CHECKLIST = [
    "Written authorization obtained from client",
    "Scope document signed (hosts, paths, actions, expiry)",
    "Staging environment isolated from production",
    "Test accounts are least-privilege / synthetic data",
    "Ops team notified of testing window",
    "Rate limits and probe caps configured",
    "PII redaction enabled in reports",
    "Audit logging enabled",
    "Rollback / incident contact identified",
]


@dataclass
class AuditEntry:
    ts: float
    action: str
    target: str
    result: str
    detail: str = ""


@dataclass
class EngagementScope:
    client: str = ""
    authorized_by: str = ""
    scope_hosts: List[str] = field(default_factory=list)
    scope_paths: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=lambda: ["passive_capture"])
    expires: str = ""
    staging_credentials_ref: str = ""
    roe_acknowledged: bool = False
    data_regions: List[str] = field(default_factory=list)

    def is_loaded(self) -> bool:
        return bool(self.client and self.scope_hosts and self.roe_acknowledged)

    def is_expired(self) -> bool:
        if not self.expires:
            return False
        try:
            from datetime import datetime, timezone
            exp = datetime.fromisoformat(self.expires.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return False

    def allows_action(self, action: str) -> bool:
        if not self.is_loaded() or self.is_expired():
            return action == "passive_capture"
        return action in self.allowed_actions

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        host = host.lower().strip(".")
        for pattern in self.scope_hosts:
            p = pattern.lower().strip(".")
            if p.startswith("*."):
                if host.endswith(p[1:]) or host == p[2:]:
                    return True
            elif host == p or host.endswith("." + p):
                return True
        return False

    def path_in_scope(self, path: str) -> bool:
        if not self.scope_paths:
            return True
        path = path or "/"
        for pattern in self.scope_paths:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif path == pattern:
                return True
        return False

    def check(self, *, action: str, host: str = "", path: str = "/") -> tuple:
        """Return (allowed: bool, reason: str)."""
        if not SCOPE_GATE_ENABLED:
            return True, "OK"
        if action != "passive_capture":
            if not self.is_loaded():
                return False, "No engagement scope loaded — load scope in Settings."
            if self.is_expired():
                return False, f"Engagement scope expired ({self.expires})."
            if not self.roe_acknowledged:
                return False, "Rules of Engagement not acknowledged."
            if not self.allows_action(action):
                return False, f"Action '{action}' not in allowed_actions."
        if host and self.scope_hosts and not self.host_in_scope(host):
            return False, f"Host '{host}' not in scope."
        if path and self.scope_paths and not self.path_in_scope(path):
            return False, f"Path '{path}' not in scope."
        return True, "OK"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngagementScope":
        return cls(
            client=d.get("client", ""),
            authorized_by=d.get("authorized_by", ""),
            scope_hosts=list(d.get("scope_hosts", [])),
            scope_paths=list(d.get("scope_paths", [])),
            allowed_actions=list(d.get("allowed_actions", ["passive_capture"])),
            expires=d.get("expires", ""),
            staging_credentials_ref=d.get("staging_credentials_ref", ""),
            roe_acknowledged=bool(d.get("roe_acknowledged", False)),
            data_regions=list(d.get("data_regions", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EngagementManager:
    """Singleton manager for scope + audit log."""

    def __init__(self):
        self.scope = EngagementScope()
        self.audit_log: List[AuditEntry] = []

    def load_scope_file(self, path: str) -> EngagementScope:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.scope = EngagementScope.from_dict(data)
        self.log("load_scope", path, "loaded", self.scope.client)
        return self.scope

    def save_scope_file(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.scope.to_dict(), f, indent=2)

    def log(self, action: str, target: str, result: str, detail: str = ""):
        self.audit_log.append(AuditEntry(
            ts=time.time(), action=action, target=target,
            result=result, detail=detail))

    def export_audit(self) -> str:
        lines = ["ENGAGEMENT AUDIT LOG", "=" * 60]
        for e in self.audit_log:
            from datetime import datetime
            ts = datetime.fromtimestamp(e.ts).isoformat(timespec="seconds")
            lines.append(f"[{ts}] {e.action} → {e.target}: {e.result}")
            if e.detail:
                lines.append(f"    {e.detail}")
        return "\n".join(lines)

    def format_roe_template(self) -> str:
        lines = [
            "RULES OF ENGAGEMENT — TEMPLATE",
            "=" * 60,
            "Copy to engagement_scope.json and customize.",
            "",
            json.dumps({
                "client": "Client Name",
                "authorized_by": "Authorized Signatory",
                "scope_hosts": ["api.example.com", "*.staging.example.com"],
                "scope_paths": ["/v1/*"],
                "allowed_actions": [
                    "passive_capture", "controlled_probe",
                    "credential_replay", "staging_access", "region_probe"],
                "expires": "2026-12-31T23:59:59Z",
                "staging_credentials_ref": "env:STAGING_API_KEY",
                "roe_acknowledged": True,
                "data_regions": ["US", "EU"],
            }, indent=2),
            "",
            "RoE CHECKLIST:",
        ]
        for i, item in enumerate(ROE_CHECKLIST, 1):
            lines.append(f"  {i}. [ ] {item}")
        return "\n".join(lines)


_manager: Optional[EngagementManager] = None


def engagement_manager() -> EngagementManager:
    global _manager
    if _manager is None:
        _manager = EngagementManager()
    return _manager
