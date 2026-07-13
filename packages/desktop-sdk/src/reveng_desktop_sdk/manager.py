"""Desktop manager: the substrate-Component composition root.

Owns the workspace, IPC client, session, service, and preferences. Exposes
the desktop's project/job/report/plugin/health operations; performs no
analysis logic of its own -- every remote call delegates straight to
``HttpIPC``/``DesktopClient``.
"""

from __future__ import annotations

from pathlib import Path

from reveng_core_substrate import HealthResult, HealthState
from reveng_public_api import (
    HealthResponse,
    JobStatusResponse,
    JobSubmitResponse,
    PluginSummary,
    ReportResponse,
)

from .config import DesktopSdkConfig
from .errors import PersistenceError
from .ipc import HttpIPC
from .preferences import Preferences, PreferencesStore
from .project import Project
from .service import DesktopService
from .session import DesktopSession
from .workspace import Workspace, WorkspaceStore

__all__ = ["DesktopManager"]


class DesktopManager:
    """Lifecycle-aware coordinator over the desktop's local state and the
    public API service."""

    component_name = "desktop-sdk.manager"
    depends_on: tuple[str, ...] = ()

    def __init__(
        self,
        config: DesktopSdkConfig | None = None,
        *,
        service: DesktopService | None = None,
        workspace_store: WorkspaceStore | None = None,
        preferences_store: PreferencesStore | None = None,
    ) -> None:
        self._config = config or DesktopSdkConfig()
        self._service = service or DesktopService(self._config)
        self._ipc = HttpIPC(self._service.client)
        self._preferences_store = preferences_store or PreferencesStore()
        self._preferences: Preferences = self._preferences_store.load()
        self._workspace_store = workspace_store or WorkspaceStore()
        self._workspace: Workspace = self._workspace_store.load(preferences=self._preferences)
        self._session = DesktopSession()

    @property
    def workspace(self) -> Workspace:
        return self._workspace

    @property
    def session(self) -> DesktopSession:
        return self._session

    @property
    def preferences(self) -> Preferences:
        return self._preferences

    @property
    def service(self) -> DesktopService:
        return self._service

    # -- substrate lifecycle -------------------------------------------------

    def initialize(self) -> None:
        self._service.start()

    def shutdown(self) -> None:
        try:
            self._workspace_store.save(self._workspace)
        except PersistenceError:
            pass
        self._service.stop()

    # -- project / workspace ---------------------------------------------------

    def open_project(self, root_path: Path, name: str | None = None) -> Project:
        project = Project.create(root_path, name)
        self._workspace.add_project(project)
        self._session.current_project = project
        return project

    def close_project(self) -> None:
        self._session.clear()

    # -- remote operations -----------------------------------------------------

    def submit_artifact(
        self,
        content: bytes,
        *,
        source_ref: str,
        hint_extension: str | None = None,
        template_name: str | None = None,
    ) -> JobSubmitResponse:
        self._service.ensure_connected()
        submission = self._ipc.submit_job(
            content,
            source_ref=source_ref,
            hint_extension=hint_extension,
            template_name=template_name,
        )
        project = self._session.current_project
        if project is not None:
            updated = project.with_artifact(submission.job_id)
            self._workspace.projects[updated.project_id] = updated
            self._session.current_project = updated
        return submission

    def refresh_job(self, job_id: str) -> JobStatusResponse:
        self._service.ensure_connected()
        return self._ipc.job_status(job_id)

    def fetch_report(self, job_id: str) -> ReportResponse:
        self._service.ensure_connected()
        report = self._ipc.job_report(job_id)
        self._session.select_report(job_id)
        return report

    def plugins(self) -> list[PluginSummary]:
        self._service.ensure_connected()
        return self._ipc.plugins()

    def health(self) -> HealthResult:
        return self._service.health()

    def health_state(self) -> HealthState:
        return self._service.health_state()

    def remote_health(self) -> HealthResponse:
        """The public API's own reported health (distinct from
        ``health()``, which reports whether this manager can reach it)."""

        self._service.ensure_connected()
        return self._ipc.health()
