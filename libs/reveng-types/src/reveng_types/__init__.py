"""Engineering shared types — no runtime domain types."""

from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict

__version__ = "0.1.0"


class JsonObject(TypedDict, total=False):
    """Loose JSON object shape for engineering tool summaries."""

    pass


class ToolSummary(TypedDict, total=False):
    ok: bool
    tool: str
    event: str
    errors: list[dict[str, Any]]
    data: dict[str, Any]


class EngineeringEvent(str, Enum):
    BOOTSTRAP_COMPLETED = "BootstrapCompleted"
    BOOTSTRAP_FAILED = "BootstrapFailed"
    VALIDATION_FAILED = "ValidationFailed"
    VALIDATION_PASSED = "ValidationPassed"
    CODEGEN_DRIFT_DETECTED = "CodegenDriftDetected"
    CODEGEN_COMPLETED = "CodegenCompleted"
    WORKSPACE_BUILD_COMPLETED = "WorkspaceBuildCompleted"
    RELEASE_TAGGED = "ReleaseTagged"
