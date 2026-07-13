"""Shared builders for static-analysis tests."""

from __future__ import annotations

from reveng_domain_producers import Artifact, ArtifactType, build_artifact
from reveng_static_analysis import AnalysisRequest


def make_artifact(
    *,
    content: bytes = b"MZ\x90\x00sample",
    artifact_type: ArtifactType = ArtifactType.PE,
) -> Artifact:
    return build_artifact(
        content=content,
        source_ref="sample.bin",
        artifact_type=artifact_type,
        producer_name="test",
        producer_version="1.0.0",
    )


def make_request(
    *,
    content: bytes = b"MZ\x90\x00sample",
    artifact_type: ArtifactType = ArtifactType.PE,
    raw_content: bytes | None = None,
) -> AnalysisRequest:
    art = make_artifact(content=content, artifact_type=artifact_type)
    body = content if raw_content is None else raw_content
    return AnalysisRequest(artifact=art, raw_content=body)
