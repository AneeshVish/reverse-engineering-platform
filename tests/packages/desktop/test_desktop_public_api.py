"""Invariant: the Phase 015 public API is frozen.

Pins ``reveng_desktop_sdk.__all__`` against an explicit snapshot so any
addition or removal is a deliberate, reviewed change. Later phases extend it
additively.
"""

from __future__ import annotations

import reveng_desktop_sdk

PHASE_015_PUBLIC_API = frozenset(
    {
        "__version__",
        "DesktopManager",
        "build_desktop_manager",
        "DesktopClient",
        "IPCProtocol",
        "HttpIPC",
        "DesktopService",
        "Project",
        "DesktopSession",
        "Preferences",
        "PreferencesStore",
        "DEFAULT_PREFERENCES_PATH",
        "Workspace",
        "WorkspaceStore",
        "DEFAULT_WORKSPACE_PATH",
        "DesktopSdkConfig",
        "load_desktop_sdk_config",
        "DESKTOP_SDK_DEFAULTS",
        "DesktopError",
        "NotFoundError",
        "JobNotReadyError",
        "RequestError",
        "ServiceError",
        "ServiceUnavailableError",
        "PersistenceError",
        "make_error",
        "guard",
    }
)


def test_public_api_matches_snapshot() -> None:
    assert frozenset(reveng_desktop_sdk.__all__) == PHASE_015_PUBLIC_API


def test_all_entries_are_importable() -> None:
    for name in reveng_desktop_sdk.__all__:
        assert hasattr(reveng_desktop_sdk, name), name


def test_all_has_no_duplicates() -> None:
    assert len(reveng_desktop_sdk.__all__) == len(set(reveng_desktop_sdk.__all__))
    assert len(reveng_desktop_sdk.__all__) == 27
