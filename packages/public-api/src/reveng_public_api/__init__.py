"""reveng-public-api — the platform's outward-facing REST/HTTP service layer.

Owner: Implementation Specification 010 (Public API / Service Layer). This
package orchestrates the full ingestion-through-reporting pipeline (domain
producers, static analysis, storage, knowledge graph, reasoning,
investigation, reporting) plus read-only plugin listing, exposing it over
FastAPI: upload endpoints, background job execution, progress/status
endpoints, and a framework-only authentication hook. It performs no analysis
logic of its own -- pure orchestration.

Job/session identity and timestamps are the one deliberate, scoped exception
to this platform's determinism invariant (see ``identifiers.py``); the
pipeline orchestration itself remains exactly as deterministic as the backend
packages it calls.

Everything re-exported here constitutes the frozen Phase 014 public API; later
Engineering Phases extend it additively.
"""

from __future__ import annotations

from .app import create_app
from .auth import AllowAllAuthHook, AuthHook, AuthPrincipal, require_principal
from .config import PUBLIC_API_DEFAULTS, PublicApiConfig, load_public_api_config
from .contracts import ClockProtocol, IdProvider
from .errors import (
    AuthError,
    JobError,
    NotFoundError,
    OrchestrationError,
    PublicApiError,
    RequestError,
    UploadError,
    guard,
    make_error,
)
from .identifiers import FixedClock, MonotonicIdProvider, SystemClock
from .init import ServiceContext, build_service
from .job_manager import JobManager
from .jobs import Job, JobState
from .orchestrator import PipelineOrchestrator, PipelineResult
from .plugins_view import list_plugins
from .schemas import (
    HealthResponse,
    JobStatusResponse,
    JobSubmitResponse,
    PluginSummary,
    ReportResponse,
    UploadResponse,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # app
    "create_app",
    # service composition
    "ServiceContext",
    "build_service",
    # orchestration
    "PipelineOrchestrator",
    "PipelineResult",
    # jobs
    "JobManager",
    "Job",
    "JobState",
    # identity / time (the scoped non-determinism exception)
    "ClockProtocol",
    "IdProvider",
    "MonotonicIdProvider",
    "SystemClock",
    "FixedClock",
    # plugins
    "list_plugins",
    # auth (framework only)
    "AuthPrincipal",
    "AuthHook",
    "AllowAllAuthHook",
    "require_principal",
    # schemas
    "UploadResponse",
    "JobSubmitResponse",
    "JobStatusResponse",
    "ReportResponse",
    "PluginSummary",
    "HealthResponse",
    # config
    "PublicApiConfig",
    "load_public_api_config",
    "PUBLIC_API_DEFAULTS",
    # errors
    "PublicApiError",
    "RequestError",
    "UploadError",
    "JobError",
    "OrchestrationError",
    "NotFoundError",
    "AuthError",
    "make_error",
    "guard",
]
