"""Invariant: the Phase 014 public API is frozen.

Pins ``reveng_public_api.__all__`` against an explicit snapshot so any
addition or removal is a deliberate, reviewed change. Later phases extend it
additively.
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


def test_public_api_matches_snapshot() -> None:
    assert frozenset(reveng_public_api.__all__) == PHASE_014_PUBLIC_API


def test_all_entries_are_importable() -> None:
    for name in reveng_public_api.__all__:
        assert hasattr(reveng_public_api, name), name


def test_all_has_no_duplicates() -> None:
    assert len(reveng_public_api.__all__) == len(set(reveng_public_api.__all__))
    assert len(reveng_public_api.__all__) == 37
