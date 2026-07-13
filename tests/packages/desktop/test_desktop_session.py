"""Desktop-sdk tests: DesktopSession -- nothing persistent, no file I/O."""

from __future__ import annotations

from pathlib import Path

from reveng_desktop_sdk.project import Project
from reveng_desktop_sdk.session import DesktopSession


def test_open_and_close_tabs() -> None:
    session = DesktopSession()
    session.open_tab("disassembly")
    session.open_tab("report")
    assert session.open_tabs == ["disassembly", "report"]

    session.open_tab("disassembly")  # duplicate, no-op
    assert session.open_tabs == ["disassembly", "report"]

    session.close_tab("disassembly")
    assert session.open_tabs == ["report"]

    session.close_tab("missing")  # no-op, does not raise


def test_select_artifact_and_report() -> None:
    session = DesktopSession()
    session.select_artifact("artifact-ref")
    session.select_report("job-000000000000")
    assert session.selected_artifact == "artifact-ref"
    assert session.selected_report_job_id == "job-000000000000"


def test_clear_resets_everything(tmp_path: Path) -> None:
    session = DesktopSession()
    session.current_project = Project.create(tmp_path)
    session.open_tab("t")
    session.select_artifact("a")
    session.select_report("r")

    session.clear()

    assert session.current_project is None
    assert session.open_tabs == []
    assert session.selected_artifact is None
    assert session.selected_report_job_id is None
