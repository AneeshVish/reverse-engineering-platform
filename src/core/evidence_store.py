"""Unified evidence graph — every tab emits structured atoms, fusion engine merges them."""

import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

# Evidence levels (L1/L2/L3 from RED TEAM plan)
L1 = "L1"
L2 = "L2"
L3 = "L3"

# Evidence kinds
OBSERVED = "OBSERVED"
EXTRACTED = "EXTRACTED"
MEASURED = "MEASURED"
INFERRED = "INFERRED"

# Confidence tiers (aligned with behavior_infer)
CONF_OBSERVED = "OBSERVED"
CONF_STRONG = "STRONG"
CONF_MODERATE = "MODERATE"
CONF_WEAK = "WEAK"


@dataclass(frozen=True)
class PlaintextEvent:
    """Unified capture event from mitmproxy, Frida, or eBPF planes."""

    timestamp_ns: int
    source_plane: str       # "mitmproxy" | "frida" | "ebpf"
    pid: int
    uid: int
    process_comm: str
    target_host: str
    target_port: int
    payload_type: str       # "request" | "response" | "tls_send" | "tls_recv"
    raw_payload: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceArtifact:
    detail: str
    source: str = ""


@dataclass
class EvidenceItem:
    claim: str
    level: str = L1
    kind: str = OBSERVED
    category: str = "network"
    confidence: str = CONF_OBSERVED
    artifacts: List[EvidenceArtifact] = field(default_factory=list)
    confounders: List[str] = field(default_factory=list)
    corroborates: List[str] = field(default_factory=list)
    falsify_by: List[str] = field(default_factory=list)
    source_tab: str = ""
    source_module: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["artifacts"] = [{"detail": a.detail, "source": a.source} for a in self.artifacts]
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceItem":
        arts = [EvidenceArtifact(**a) if isinstance(a, dict) else a
                for a in d.get("artifacts", [])]
        return cls(
            id=d.get("id", uuid.uuid4().hex[:12]),
            claim=d.get("claim", ""),
            level=d.get("level", L1),
            kind=d.get("kind", OBSERVED),
            category=d.get("category", "network"),
            confidence=d.get("confidence", CONF_OBSERVED),
            artifacts=arts,
            confounders=list(d.get("confounders", [])),
            corroborates=list(d.get("corroborates", [])),
            falsify_by=list(d.get("falsify_by", [])),
            source_tab=d.get("source_tab", ""),
            source_module=d.get("source_module", ""),
        )


class EvidenceStore:
    """In-memory evidence graph for the current engagement session."""

    def __init__(self):
        self._items: Dict[str, EvidenceItem] = {}

    def add(self, item: EvidenceItem) -> EvidenceItem:
        self._items[item.id] = item
        return item

    def add_simple(self, claim, *, level=L1, kind=OBSERVED, category="network",
                   confidence=CONF_OBSERVED, detail="", source="", source_tab="",
                   source_module="", confounders=None) -> EvidenceItem:
        item = EvidenceItem(
            claim=claim, level=level, kind=kind, category=category,
            confidence=confidence,
            artifacts=[EvidenceArtifact(detail, source)] if detail else [],
            confounders=list(confounders or []),
            source_tab=source_tab, source_module=source_module,
        )
        return self.add(item)

    def get(self, item_id: str) -> Optional[EvidenceItem]:
        return self._items.get(item_id)

    def link(self, item_id: str, corroborates_id: str):
        if item_id in self._items and corroborates_id in self._items:
            if corroborates_id not in self._items[item_id].corroborates:
                self._items[item_id].corroborates.append(corroborates_id)

    def all_items(self) -> List[EvidenceItem]:
        return list(self._items.values())

    def by_category(self, category: str) -> List[EvidenceItem]:
        return [i for i in self._items.values() if i.category == category]

    def by_level(self, level: str) -> List[EvidenceItem]:
        return [i for i in self._items.values() if i.level == level]

    def clear(self):
        self._items.clear()

    def fused_groups(self) -> List[List[EvidenceItem]]:
        """Legacy union-find groups (prefer fuse_findings() for architecture conclusions)."""
        parent = {i.id: i.id for i in self._items.values()}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for item in self._items.values():
            for cid in item.corroborates:
                if cid in self._items:
                    union(item.id, cid)

        groups: Dict[str, List[EvidenceItem]] = {}
        for item in self._items.values():
            root = find(item.id)
            groups.setdefault(root, []).append(item)
        return list(groups.values())

    def fuse_findings(self, flows=None, probe_results=None):
        from src.core import evidence_fusion
        return evidence_fusion.fuse(store=self, flows=flows or [],
                                    probe_results=probe_results or [])

    def format_fusion_report(self, flows=None, probe_results=None) -> str:
        from src.core import evidence_fusion
        return evidence_fusion.format_fusion_report(
            self.fuse_findings(flows=flows, probe_results=probe_results))

    def format_report(self, *, flows=None, probe_results=None, include_raw=True) -> str:
        fusion = self.format_fusion_report(flows=flows, probe_results=probe_results)
        if not include_raw:
            return fusion
        items = sorted(self.all_items(),
                       key=lambda i: (i.level, i.category, i.claim))
        if not items:
            return fusion
        lines = [fusion, "", "=" * 60, "RAW EVIDENCE ATOMS", "=" * 60]
        current = None
        for item in items:
            if item.category != current:
                current = item.category
                lines.append(f"\n## {current}")
            badge = f"[{item.level}/{item.confidence}]"
            lines.append(f"\n{badge} {item.claim}")
            for a in item.artifacts:
                src = f" ({a.source})" if a.source else ""
                lines.append(f"    • {a.detail}{src}")
        return "\n".join(lines)


# Session singleton — modules import and write here during an engagement.
_session_store: Optional[EvidenceStore] = None


def session_store() -> EvidenceStore:
    global _session_store
    if _session_store is None:
        _session_store = EvidenceStore()
    return _session_store


def reset_session_store():
    global _session_store
    _session_store = EvidenceStore()
