"""Domain-producer tests: substrate lifecycle participation and health."""

from __future__ import annotations

from reveng_core_substrate import Application, HealthState
from reveng_domain_producers import (
    ProducerManager,
    ProducerRegistry,
    register_builtin_producers,
)


def test_manager_is_a_lifecycle_component() -> None:
    mgr = ProducerManager(ProducerRegistry())
    assert mgr.component_name == "domain-producers.manager"
    assert mgr.depends_on == ()


def test_initialize_registers_reference_producers() -> None:
    reg = ProducerRegistry()
    mgr = ProducerManager(reg)
    assert len(reg) == 0
    mgr.initialize()
    assert len(reg) == 12


def test_participates_in_application_lifecycle() -> None:
    reg = ProducerRegistry()
    mgr = ProducerManager(reg)
    app = Application()
    app.register_component(mgr)
    app.initialize()
    assert len(reg) == 12
    assert mgr.discover()  # producers discoverable after app init
    app.shutdown()  # clean no-op shutdown


def test_preloaded_registry_not_double_registered() -> None:
    reg = ProducerRegistry()
    register_builtin_producers(reg)
    mgr = ProducerManager(reg)
    mgr.initialize()  # must not raise on duplicate registration
    assert len(reg) == 12


def test_health_aggregates_producers() -> None:
    reg = ProducerRegistry()
    mgr = ProducerManager(reg)
    mgr.initialize()
    assert mgr.health_state() is HealthState.HEALTHY
