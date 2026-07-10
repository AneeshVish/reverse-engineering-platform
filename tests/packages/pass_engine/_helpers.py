"""Shared test doubles for the pass-engine suite."""

from __future__ import annotations

from reveng_domain_producers import Artifact, ArtifactType, build_artifact
from reveng_pass_engine import (
    Applicability,
    Capability,
    ExecutionReport,
    ExecutionRequest,
    Pass,
    PassContext,
    PassMetadata,
    PassResult,
    PassStatus,
    Prerequisite,
)


def result_of(report: ExecutionReport, pass_id: str) -> PassResult:
    """Return a report's result for ``pass_id``, asserting it exists."""

    result = report.by_id(pass_id)
    assert result is not None, f"no result for {pass_id}"
    return result


def make_artifact(
    artifact_type: ArtifactType = ArtifactType.RAW_BINARY,
    *,
    content: bytes = b"data",
    capabilities: tuple[str, ...] = (),
) -> Artifact:
    return build_artifact(
        content=content,
        source_ref="ref",
        artifact_type=artifact_type,
        producer_name="test",
        producer_version="1.0.0",
        capabilities=capabilities,
    )


def make_request(*artifacts: Artifact) -> ExecutionRequest:
    return ExecutionRequest(artifacts=artifacts or (make_artifact(),))


class RecordingPass(Pass):
    """A deterministic pass that records execution order into a shared log."""

    def __init__(
        self,
        identifier: str,
        *,
        version: str = "1.0.0",
        dependencies: tuple[str, ...] = (),
        provides: tuple[str, ...] = (),
        requires: tuple[str, ...] = (),
        artifact_types: tuple[ArtifactType, ...] = (),
        log: list[str] | None = None,
        payload: object | None = None,
    ) -> None:
        self._meta = PassMetadata(
            identifier=identifier,
            version=version,
            capabilities=tuple(Capability(c) for c in provides),
            prerequisites=tuple(Prerequisite(r) for r in requires),
            dependencies=dependencies,
            applicability=Applicability(artifact_types),
        )
        self._log = log if log is not None else []
        self._payload = payload

    @property
    def metadata(self) -> PassMetadata:
        return self._meta

    def run(self, context: PassContext) -> PassResult:
        self._log.append(self._meta.identifier)
        return PassResult(self._meta.identifier, PassStatus.COMPLETED, payload=self._payload)


class FailingPass(RecordingPass):
    """A pass that raises to exercise the failure boundary."""

    def run(self, context: PassContext) -> PassResult:
        self._log.append(self._meta.identifier)
        raise RuntimeError("boom")


class ReturnFailurePass(RecordingPass):
    """A pass that returns a FAILED result with a chosen failure class."""

    def __init__(self, *args: object, failure_class, **kwargs: object) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._failure_class = failure_class

    def run(self, context: PassContext) -> PassResult:
        self._log.append(self._meta.identifier)
        return PassResult(
            self._meta.identifier,
            PassStatus.FAILED,
            failure_class=self._failure_class,
        )
