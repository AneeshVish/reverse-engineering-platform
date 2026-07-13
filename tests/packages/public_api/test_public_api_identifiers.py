"""Public-api tests: the scoped non-determinism exception (identity + time)."""

from __future__ import annotations

from reveng_public_api import FixedClock, MonotonicIdProvider


def test_monotonic_id_provider_is_predictable() -> None:
    provider_a = MonotonicIdProvider()
    provider_b = MonotonicIdProvider()
    ids_a = [provider_a.new_id("job") for _ in range(3)]
    ids_b = [provider_b.new_id("job") for _ in range(3)]
    assert ids_a == ids_b == ["job-000000000000", "job-000000000001", "job-000000000002"]


def test_monotonic_id_provider_respects_start() -> None:
    provider = MonotonicIdProvider(start=5)
    assert provider.new_id("job") == "job-000000000005"


def test_fixed_clock_only_advances_when_told() -> None:
    clock = FixedClock(10.0)
    assert clock.now() == 10.0
    assert clock.now() == 10.0
    clock.advance(2.5)
    assert clock.now() == 12.5
