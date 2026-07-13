"""reveng-reasoning — the deterministic inference engine.

Owner: Implementation Specification 005 (Reasoning). This package consumes the
Knowledge Graph and the Evidence Store and derives new facts through explicit
rules, emitting immutable ``Inference`` objects. It is not AI: no LLM, ML,
embeddings, classifiers, probabilistic scoring, malware/threat intelligence,
heuristics, or pattern matching beyond explicit rules. Every conclusion is
deterministic and carries its exact evidence and graph chain.

Everything re-exported here constitutes the frozen Phase 010 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .config import REASONING_DEFAULTS, ReasoningConfig, load_reasoning_config
from .contracts import ReasoningConsumer, ReasoningProvider, RuleProvider
from .engine import ReasoningEngine, ReasoningResult
from .errors import (
    IdentityError,
    ReasoningError,
    RegistrationError,
    RuleError,
    SerializationError,
    ValidationError,
    guard,
    make_error,
)
from .executor import RuleExecutor
from .inference import (
    Inference,
    InferenceExplanation,
    InferenceID,
    InferenceKind,
    InferenceState,
    build_inference,
)
from .init import build_reasoning_engine
from .manager import ReasoningManager
from .planner import ReasoningPlan, ReasoningPlanner
from .properties import PropertyBag, PropertyKey, PropertyValue
from .query import ReasoningQuery, ReasoningQueryFilter, ReasoningQueryResult
from .reference import REFERENCE_RULE_TYPES, register_builtin_rules
from .registry import RuleRegistry
from .rules import (
    DEFAULT_PRIORITY,
    Rule,
    RuleContext,
    RuleID,
    RuleMetadata,
    RuleRequirement,
    RuleResult,
)
from .serialization import ReasoningDeserializer, ReasoningSerializer
from .validation import ResultValidator, validate_result

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # inference model
    "InferenceKind",
    "InferenceState",
    "InferenceExplanation",
    "InferenceID",
    "Inference",
    "build_inference",
    # properties
    "PropertyKey",
    "PropertyValue",
    "PropertyBag",
    # rules
    "RuleID",
    "RuleRequirement",
    "RuleMetadata",
    "RuleContext",
    "RuleResult",
    "Rule",
    "DEFAULT_PRIORITY",
    # framework
    "RuleRegistry",
    "ReasoningPlanner",
    "ReasoningPlan",
    "RuleExecutor",
    "ReasoningEngine",
    "ReasoningResult",
    "ReasoningManager",
    "build_reasoning_engine",
    "register_builtin_rules",
    "REFERENCE_RULE_TYPES",
    # validation
    "validate_result",
    "ResultValidator",
    # serialization
    "ReasoningSerializer",
    "ReasoningDeserializer",
    # query
    "ReasoningQuery",
    "ReasoningQueryFilter",
    "ReasoningQueryResult",
    # contracts
    "ReasoningProvider",
    "ReasoningConsumer",
    "RuleProvider",
    # config
    "ReasoningConfig",
    "load_reasoning_config",
    "REASONING_DEFAULTS",
    # errors
    "ReasoningError",
    "RegistrationError",
    "RuleError",
    "ValidationError",
    "SerializationError",
    "IdentityError",
    "make_error",
    "guard",
]
