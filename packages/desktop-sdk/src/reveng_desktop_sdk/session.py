"""Desktop session state.

Tracks the current project, open tabs, and selections. Nothing persistent --
the one deliberately mutable shape in this package, mirroring
``reveng_public_api.jobs.Job``'s precedent for representing genuinely
time-varying, in-memory-only state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .project import Project

__all__ = ["DesktopSession"]


@dataclass
class DesktopSession:
    """In-memory-only UI session state: current project, tabs, selections."""

    current_project: Project | None = None
    open_tabs: list[str] = field(default_factory=list)
    selected_artifact: str | None = None
    selected_report_job_id: str | None = None

    def open_tab(self, tab: str) -> None:
        if tab not in self.open_tabs:
            self.open_tabs.append(tab)

    def close_tab(self, tab: str) -> None:
        if tab in self.open_tabs:
            self.open_tabs.remove(tab)

    def select_artifact(self, artifact_ref: str | None) -> None:
        self.selected_artifact = artifact_ref

    def select_report(self, job_id: str | None) -> None:
        self.selected_report_job_id = job_id

    def clear(self) -> None:
        self.current_project = None
        self.open_tabs = []
        self.selected_artifact = None
        self.selected_report_job_id = None
