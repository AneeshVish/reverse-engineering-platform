"""Invariant: the public API is frozen.

Pins ``reveng_public_api.__all__`` against an explicit snapshot so any
addition or removal is a deliberate, reviewed change. ``PHASE_014_PUBLIC_API``
is the original Phase 014 freeze point; ``PHASE_017_ADDITIONS`` is what Phase
017 (Pipeline Query API) added on top of it, additively -- nothing from Phase
014 was removed or renamed.
"""

from __future__ import annotations

import reveng_public_api

PHASE_014_PUBLIC_API = frozenset(
    {
        "__version__",
        "create_app",
        "ServiceContext",
        "build_service",
        "PipelineOrchestrator",
        "PipelineResult",
        "JobManager",
        "Job",
        "JobState",
        "ClockProtocol",
        "IdProvider",
        "MonotonicIdProvider",
        "SystemClock",
        "FixedClock",
        "list_plugins",
        "AuthPrincipal",
        "AuthHook",
        "AllowAllAuthHook",
        "require_principal",
        "UploadResponse",
        "JobSubmitResponse",
        "JobStatusResponse",
        "ReportResponse",
        "PluginSummary",
        "HealthResponse",
        "PublicApiConfig",
        "load_public_api_config",
        "PUBLIC_API_DEFAULTS",
        "PublicApiError",
        "RequestError",
        "UploadError",
        "JobError",
        "OrchestrationError",
        "NotFoundError",
        "AuthError",
        "make_error",
        "guard",
    }
)

PHASE_017_ADDITIONS = frozenset(
    {
        "PipelinePhase",
        "PhaseTiming",
        "JobSummary",
        "JobDetail",
        "JobListResponse",
        "PhaseTimingModel",
        "InvestigationResponse",
        "EvidenceResponse",
        "ReasoningResponse",
        "GraphResponse",
    }
)

PHASE_017_PUBLIC_API = PHASE_014_PUBLIC_API | PHASE_017_ADDITIONS


def test_public_api_matches_snapshot() -> None:
    assert frozenset(reveng_public_api.__all__) == PHASE_017_PUBLIC_API


def test_phase_014_surface_is_unchanged() -> None:
    """No Phase 014 export was removed or renamed -- Phase 017 is additive-only."""

    assert PHASE_014_PUBLIC_API <= frozenset(reveng_public_api.__all__)


def test_all_entries_are_importable() -> None:
    for name in reveng_public_api.__all__:
        assert hasattr(reveng_public_api, name), name


def test_all_has_no_duplicates() -> None:
    assert len(reveng_public_api.__all__) == len(set(reveng_public_api.__all__))
    assert len(reveng_public_api.__all__) == 47
