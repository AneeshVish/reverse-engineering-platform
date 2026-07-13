"""reveng-desktop-sdk — the desktop's integration/IPC client library.

Owner: Engineering Phase 015 (Desktop Integration / IPC). This package
connects the desktop application to the Phase-014 public API service: a
typed HTTP client, service lifecycle (attach-or-launch, reconnect), local
UI-adjacent state (workspace/project/session/preferences), and a
substrate-Component composition root (``DesktopManager``) exposing
project/job/report/plugin/health operations. It performs no analysis,
reasoning, investigation, reporting, or persistence of pipeline results of
its own -- everything goes through the public API.

This phase deliberately does not touch the legacy desktop GUI (repo-root
``src/gui/*`` and ``main.py``) or add runtime code to ``apps/reveng-desktop``
-- see the package README for why. It is proven standalone via its own test
suite and a manual smoke test.

Everything re-exported here constitutes the frozen Phase 015 public API;
later Engineering Phases extend it additively.
"""

from __future__ import annotations

from .client import DesktopClient
from .config import DESKTOP_SDK_DEFAULTS, DesktopSdkConfig, load_desktop_sdk_config
from .contracts import IPCProtocol
from .errors import (
    DesktopError,
    JobNotReadyError,
    NotFoundError,
    PersistenceError,
    RequestError,
    ServiceError,
    ServiceUnavailableError,
    guard,
    make_error,
)
from .init import build_desktop_manager
from .ipc import HttpIPC
from .manager import DesktopManager
from .preferences import DEFAULT_PREFERENCES_PATH, Preferences, PreferencesStore
from .project import Project
from .service import DesktopService
from .session import DesktopSession
from .workspace import DEFAULT_WORKSPACE_PATH, Workspace, WorkspaceStore

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # manager & construction
    "DesktopManager",
    "build_desktop_manager",
    # client & transport
    "DesktopClient",
    "IPCProtocol",
    "HttpIPC",
    # service lifecycle
    "DesktopService",
    # local state models
    "Project",
    "DesktopSession",
    "Preferences",
    "PreferencesStore",
    "DEFAULT_PREFERENCES_PATH",
    "Workspace",
    "WorkspaceStore",
    "DEFAULT_WORKSPACE_PATH",
    # config
    "DesktopSdkConfig",
    "load_desktop_sdk_config",
    "DESKTOP_SDK_DEFAULTS",
    # errors
    "DesktopError",
    "NotFoundError",
    "JobNotReadyError",
    "RequestError",
    "ServiceError",
    "ServiceUnavailableError",
    "PersistenceError",
    "make_error",
    "guard",
]
