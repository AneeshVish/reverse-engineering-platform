"""Health contracts and aggregation.

Defines the concrete ``HealthReport`` value and a ``HealthAggregator`` that
polls registered health checks and reduces them to a single overall state. The
reduction is monotonic in severity: any UNHEALTHY makes the whole UNHEALTHY,
otherwise any DEGRADED makes it DEGRADED, otherwise any UNKNOWN makes it UNKNOWN.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .contracts import HealthState
from .errors import RegistryError

__all__ = ["HealthResult", "HealthCheck", "HealthAggregator"]


@dataclass(frozen=True)
class HealthResult:
    """Concrete health report for a component."""

    state: HealthState
    detail: str = ""


# A health check is any zero-arg callable returning a HealthResult.
HealthCheck = Callable[[], HealthResult]

_SEVERITY = {
    HealthState.HEALTHY: 0,
    HealthState.UNKNOWN: 1,
    HealthState.DEGRADED: 2,
    HealthState.UNHEALTHY: 3,
}


@dataclass
class _Aggregate:
    overall: HealthState
    components: dict[str, HealthResult] = field(default_factory=dict)


class HealthAggregator:
    """Collects named health checks and computes an overall state."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._checks: dict[str, HealthCheck] = {}

    def register(self, name: str, check: HealthCheck) -> None:
        with self._lock:
            if name in self._checks:
                raise RegistryError("duplicate health check", key=name)
            self._checks[name] = check

    def evaluate(self) -> _Aggregate:
        """Run all checks and reduce to an overall state.

        A check that raises is recorded as UNHEALTHY for that component rather
        than being allowed to propagate.
        """

        with self._lock:
            checks = dict(self._checks)

        components: dict[str, HealthResult] = {}
        for name in sorted(checks):
            try:
                components[name] = checks[name]()
            except Exception as exc:  # noqa: BLE001 - health probes must not throw out
                components[name] = HealthResult(HealthState.UNHEALTHY, f"check raised: {exc}")

        overall = HealthState.HEALTHY
        for result in components.values():
            if _SEVERITY[result.state] > _SEVERITY[overall]:
                overall = result.state
        return _Aggregate(overall=overall, components=components)
