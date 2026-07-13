"""Desktop-sdk tests: HttpIPC delegation and the IPCProtocol seam."""

from __future__ import annotations

from _desktop_helpers import TEST_ARTIFACT_BYTES, make_test_client
from reveng_desktop_sdk.contracts import IPCProtocol
from reveng_desktop_sdk.ipc import HttpIPC


def test_http_ipc_is_an_ipc_protocol() -> None:
    ipc = HttpIPC(make_test_client())
    assert isinstance(ipc, IPCProtocol)


def test_http_ipc_delegates_to_client() -> None:
    client = make_test_client()
    ipc = HttpIPC(client)

    upload = ipc.upload(TEST_ARTIFACT_BYTES, source_ref="s")
    assert upload.artifact_ref

    submission = ipc.submit_job(TEST_ARTIFACT_BYTES, source_ref="s")
    status = client.poll_job(submission.job_id, interval=0.02, timeout=5.0)
    assert status.state == "completed"

    report = ipc.job_report(submission.job_id)
    assert report.content

    assert ipc.plugins()
    assert ipc.health().state == "healthy"
    assert ipc.job_status(submission.job_id).state == "completed"
