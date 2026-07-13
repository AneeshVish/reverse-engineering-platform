"""reveng-investigation — the analyst-facing case-construction layer.

Owner: Implementation Specification 007 (Investigation). This package consumes
immutable ``Inference`` objects, the Knowledge Graph, and the Evidence Repository
and groups them into deterministic investigation cases, findings, timelines, and
evidence chains. It performs no new reasoning, creates no inferences, and mutates
nothing upstream — it is purely an organization layer. Every finding is fully
traceable to the originating inference, evidence, and graph elements.

Everything re-exported here constitutes the frozen Phase 011 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .builders import InvestigationBuilder, InvestigationView
from .case import CaseID, CasePriority, CaseStatus, InvestigationCase
from .chain import EvidenceChain, GraphChain, InferenceChain, chains_for
from .config import (
    INVESTIGATION_DEFAULTS,
    InvestigationConfig,
    load_investigation_config,
)
from .contracts import InvestigationConsumer, InvestigationProvider
from .errors import (
    CaseError,
    FindingError,
    InvestigationError,
    SerializationError,
    ValidationError,
    guard,
    make_error,
)
from .finding import (
    Finding,
    FindingExplanation,
    FindingID,
    FindingKind,
    FindingSeverity,
    build_finding,
)
from .indexing import CaseIndex, EvidenceIndex, FindingIndex, InferenceIndex
from .init import build_investigation_manager
from .manager import InvestigationManager
from .properties import PropertyBag, PropertyKey, PropertyValue
from .query import (
    InvestigationQuery,
    InvestigationQueryFilter,
    InvestigationQueryResult,
)
from .reference import REFERENCE_INVESTIGATION_TYPES, run_reference_investigations
from .serialization import InvestigationDeserializer, InvestigationSerializer
from .timeline import Timeline, build_timeline
from .validation import CaseValidator, validate_case

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # finding model
    "FindingKind",
    "FindingSeverity",
    "FindingID",
    "FindingExplanation",
    "Finding",
    "build_finding",
    # case model
    "CaseStatus",
    "CasePriority",
    "CaseID",
    "InvestigationCase",
    # chains
    "InferenceChain",
    "EvidenceChain",
    "GraphChain",
    "chains_for",
    # timeline
    "Timeline",
    "build_timeline",
    # properties
    "PropertyKey",
    "PropertyValue",
    "PropertyBag",
    # builders
    "InvestigationBuilder",
    "InvestigationView",
    "REFERENCE_INVESTIGATION_TYPES",
    "run_reference_investigations",
    # validation
    "validate_case",
    "CaseValidator",
    # indexing
    "CaseIndex",
    "FindingIndex",
    "EvidenceIndex",
    "InferenceIndex",
    # query
    "InvestigationQuery",
    "InvestigationQueryFilter",
    "InvestigationQueryResult",
    # serialization
    "InvestigationSerializer",
    "InvestigationDeserializer",
    # contracts
    "InvestigationProvider",
    "InvestigationConsumer",
    # config
    "InvestigationConfig",
    "load_investigation_config",
    "INVESTIGATION_DEFAULTS",
    # manager
    "InvestigationManager",
    "build_investigation_manager",
    # errors
    "InvestigationError",
    "CaseError",
    "FindingError",
    "ValidationError",
    "SerializationError",
    "make_error",
    "guard",
]
