"""reveng-pass-engine — deterministic pass execution framework.

Owner: Implementation Specification 003 (Pass Execution Engine). This package
coordinates analysis passes over normalized ``Artifact`` objects: registration,
dependency-graph construction, deterministic planning, and synchronous scheduling.
It performs no analysis and interprets no pass output — a pass's payload is
opaque to the engine.

Out of scope this phase (later phases): parallel/worker-pool/distributed
scheduling, checkpointing, caching, storage, evidence, and everything above the
execution substrate.

Everything re-exported here constitutes the frozen Phase 005 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .config import (
    PASS_ENGINE_DEFAULTS,
    PassEngineConfig,
    load_pass_engine_config,
)
from .context import PassContext
from .contracts import (
    Applicability,
    Capability,
    ExecutionRequest,
    ExecutionRequirements,
    Prerequisite,
)
from .errors import (
    CancellationError,
    DependencyError,
    ExecutionError,
    PassError,
    PlanningError,
    PrerequisiteError,
    RegistrationError,
    guard,
    make_error,
)
from .executor import Executor
from .init import build_engine
from .manager import PassEngineManager
from .passes import Pass, PassMetadata, PassState
from .pipeline import Pipeline
from .planner import ExecutionPlan, Planner
from .registry import PassRegistry
from .results import ExecutionReport, FailureClass, PassResult, PassStatus
from .scheduler import CancellationToken, Scheduler

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # pass model
    "Pass",
    "PassMetadata",
    "PassState",
    # contracts
    "Capability",
    "Prerequisite",
    "Applicability",
    "ExecutionRequirements",
    "ExecutionRequest",
    "PassContext",
    # results
    "PassStatus",
    "FailureClass",
    "PassResult",
    "ExecutionReport",
    # framework
    "PassRegistry",
    "Planner",
    "ExecutionPlan",
    "Scheduler",
    "CancellationToken",
    "Executor",
    "Pipeline",
    "PassEngineManager",
    "build_engine",
    # config
    "PassEngineConfig",
    "load_pass_engine_config",
    "PASS_ENGINE_DEFAULTS",
    # errors
    "PassError",
    "RegistrationError",
    "PlanningError",
    "DependencyError",
    "PrerequisiteError",
    "ExecutionError",
    "CancellationError",
    "make_error",
    "guard",
]
