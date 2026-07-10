"""Substrate tests: health contracts and aggregation."""

from __future__ import annotations

import pytest
from reveng_core_substrate import (
    HealthAggregator,
    HealthResult,
    HealthState,
    RegistryError,
)


def _agg(**checks: HealthState) -> HealthState:
    a = HealthAggregator()
    for name, state in checks.items():
        a.register(name, (lambda s=state: HealthResult(s)))  # type: ignore[misc]
    return a.evaluate().overall


def test_all_healthy_is_healthy() -> None:
    assert _agg(a=HealthState.HEALTHY, b=HealthState.HEALTHY) is HealthState.HEALTHY


def test_empty_aggregator_is_healthy() -> None:
    assert HealthAggregator().evaluate().overall is HealthState.HEALTHY


def test_unhealthy_dominates() -> None:
    assert (
        _agg(a=HealthState.HEALTHY, b=HealthState.DEGRADED, c=HealthState.UNHEALTHY)
        is HealthState.UNHEALTHY
    )


def test_degraded_beats_unknown_and_healthy() -> None:
    assert (
        _agg(a=HealthState.HEALTHY, b=HealthState.UNKNOWN, c=HealthState.DEGRADED)
        is HealthState.DEGRADED
    )


def test_unknown_beats_healthy() -> None:
    assert _agg(a=HealthState.HEALTHY, b=HealthState.UNKNOWN) is HealthState.UNKNOWN


def test_raising_check_recorded_as_unhealthy_not_propagated() -> None:
    a = HealthAggregator()

    def boom() -> HealthResult:
        raise RuntimeError("probe exploded")

    a.register("bad", boom)
    a.register("good", lambda: HealthResult(HealthState.HEALTHY))

    result = a.evaluate()
    assert result.overall is HealthState.UNHEALTHY
    assert result.components["bad"].state is HealthState.UNHEALTHY
    assert "probe exploded" in result.components["bad"].detail
    assert result.components["good"].state is HealthState.HEALTHY


def test_components_reported_per_name() -> None:
    a = HealthAggregator()
    a.register("svc", lambda: HealthResult(HealthState.DEGRADED, "slow"))
    result = a.evaluate()
    assert result.components["svc"].detail == "slow"


def test_duplicate_check_rejected() -> None:
    a = HealthAggregator()
    a.register("x", lambda: HealthResult(HealthState.HEALTHY))
    with pytest.raises(RegistryError):
        a.register("x", lambda: HealthResult(HealthState.HEALTHY))
