"""Public-api tests: the pipeline orchestrator chains all 9 backend calls in order."""

from __future__ import annotations

from _public_api_helpers import TEST_ARTIFACT_BYTES, make_recording_orchestrator


def test_orchestrator_calls_backends_in_order() -> None:
    order: list[str] = []
    orchestrator = make_recording_orchestrator(order)

    result = orchestrator.run(TEST_ARTIFACT_BYTES, source_ref="s")

    assert order == [
        "produce",
        "analyze",
        "graph.build",
        "reasoning.run",
        "investigation.build",
        "reporting.build",
        "reporting.render",
    ]
    assert result.artifact_ref
    assert result.rendered


def test_orchestrator_is_deterministic_for_identical_content() -> None:
    order_a: list[str] = []
    order_b: list[str] = []
    result_a = make_recording_orchestrator(order_a).run(TEST_ARTIFACT_BYTES, source_ref="s")
    result_b = make_recording_orchestrator(order_b).run(TEST_ARTIFACT_BYTES, source_ref="s")

    assert result_a.artifact_ref == result_b.artifact_ref
    assert result_a.rendered == result_b.rendered
