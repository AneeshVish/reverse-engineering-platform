# -*- coding: utf-8 -*-
"""Shared Pipeline Workspace UI-state machine (Phase 016 spec, 10.5).

Every Pipeline Workspace destination renders one of these states explicitly
instead of a generic spinner. ``COMPLETED`` is not terminal -- starting a new
operation (e.g. "Generate Report") cycles a page back to ``GENERATING``.
"""

from __future__ import annotations

from enum import Enum


class PipelineState(str, Enum):
    NOT_INITIALIZED = "not_initialized"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    OFFLINE = "offline"


# Small style/label mapping so every page renders states consistently rather
# than each widget inventing its own text/color.
_STATE_LABELS: dict[PipelineState, str] = {
    PipelineState.NOT_INITIALIZED: "Not initialized",
    PipelineState.CONNECTING: "Connecting…",
    PipelineState.CONNECTED: "Connected",
    PipelineState.GENERATING: "Generating…",
    PipelineState.COMPLETED: "Completed",
    PipelineState.FAILED: "Failed",
    PipelineState.OFFLINE: "Offline",
}

# Distinct styling for Failed (a real pipeline failure) vs Offline (we can't
# currently tell) -- objectName values consumed by the app's QSS.
_STATE_OBJECT_NAMES: dict[PipelineState, str] = {
    PipelineState.NOT_INITIALIZED: "StateDim",
    PipelineState.CONNECTING: "StateDim",
    PipelineState.CONNECTED: "StateOk",
    PipelineState.GENERATING: "StateBusy",
    PipelineState.COMPLETED: "StateOk",
    PipelineState.FAILED: "StateError",
    PipelineState.OFFLINE: "StateWarn",
}


def state_label(state: PipelineState) -> str:
    return _STATE_LABELS[state]


def state_object_name(state: PipelineState) -> str:
    return _STATE_OBJECT_NAMES[state]
