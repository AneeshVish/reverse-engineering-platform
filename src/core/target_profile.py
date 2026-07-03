"""Unified target profile — single session object linking binary, bundle, and network."""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set


@dataclass
class TargetProfile:
    """Everything we know about the current engagement target."""
    path: str = ""
    kind: str = ""          # binary | app | folder | archive
    name: str = ""
    arch: str = ""
    is_electron: bool = False
    electron_src_dir: str = ""

    # Static intel
    static_hosts: Set[str] = field(default_factory=set)
    static_endpoints: List[str] = field(default_factory=list)
    architecture_hits: List[Dict[str, Any]] = field(default_factory=list)
    feature_flags: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)

    # Live intel
    live_hosts: Set[str] = field(default_factory=set)
    captured_flow_count: int = 0

    # Analysis results reference
    analysis_results: Optional[Dict[str, Any]] = None

    @classmethod
    def from_path(cls, path: str) -> "TargetProfile":
        p = path.rstrip("/") if path else ""
        name = os.path.basename(p) if p else ""
        kind = "binary"
        if p.endswith(".app") or (p.endswith(".app/Contents/MacOS") or ".app/" in p):
            kind = "app"
        elif os.path.isdir(p):
            kind = "folder"
        elif p.endswith((".zip", ".apk", ".ipa", ".tar", ".tar.gz", ".tgz")):
            kind = "archive"
        return cls(path=p, kind=kind, name=name)

    def merge_architecture_intel(self, intel: Dict[str, Any]):
        self.architecture_hits.extend(intel.get("hits", []))
        self.feature_flags.extend(intel.get("feature_flags", []))
        for ep in intel.get("endpoints", []):
            if ep not in self.static_endpoints:
                self.static_endpoints.append(ep)
        for h in intel.get("hosts", []):
            self.static_hosts.add(h.lower())

    def merge_analysis(self, results: Dict[str, Any]):
        self.analysis_results = results
        bi = results.get("binary_info", {})
        self.arch = bi.get("arch", self.arch)
        for ep in results.get("endpoints", []):
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("host", "")
            else:
                url = str(ep)
            if url and url not in self.static_endpoints:
                self.static_endpoints.append(url)

    def summary(self) -> str:
        lines = [
            f"Target: {self.name or '(none)'}",
            f"Kind: {self.kind}  Arch: {self.arch or 'unknown'}",
            f"Electron: {'yes' if self.is_electron else 'no'}",
            f"Static hosts: {len(self.static_hosts)}  Endpoints: {len(self.static_endpoints)}",
            f"Architecture hits: {len(self.architecture_hits)}  Flags: {len(self.feature_flags)}",
            f"Secrets: {len(self.secrets)}  Live hosts: {len(self.live_hosts)}",
            f"Captured flows: {self.captured_flow_count}",
        ]
        return "\n".join(lines)


_profile: Optional[TargetProfile] = None


def session_profile() -> TargetProfile:
    global _profile
    if _profile is None:
        _profile = TargetProfile()
    return _profile


def set_session_profile(profile: TargetProfile):
    global _profile
    _profile = profile
