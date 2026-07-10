"""Substrate tests: application lifecycle, ordering, hooks, failure states."""

from __future__ import annotations

import pytest
from reveng_core_substrate import Application, LifecycleError, LifecycleState


class Recorder:
    def __init__(self, name: str, deps: tuple[str, ...] = (), log: list[str] | None = None) -> None:
        self.component_name = name
        self.depends_on = deps
        self.log = log if log is not None else []

    def initialize(self) -> None:
        self.log.append(f"init:{self.component_name}")

    def shutdown(self) -> None:
        self.log.append(f"stop:{self.component_name}")


def test_states_progress_through_lifecycle() -> None:
    app = Application()
    assert app.state is LifecycleState.CREATED
    app.initialize()
    assert app.state is LifecycleState.READY
    app.shutdown()
    assert app.state is LifecycleState.STOPPED


def test_dependency_order_and_reverse_shutdown() -> None:
    log: list[str] = []
    app = Application()
    app.register_component(Recorder("c", ("b",), log))
    app.register_component(Recorder("b", ("a",), log))
    app.register_component(Recorder("a", (), log))
    app.initialize()
    app.shutdown()
    assert log == [
        "init:a",
        "init:b",
        "init:c",
        "stop:c",
        "stop:b",
        "stop:a",
    ]


def test_registration_order_breaks_ties_deterministically() -> None:
    log: list[str] = []
    app = Application()
    app.register_component(Recorder("z", (), log))
    app.register_component(Recorder("y", (), log))
    app.initialize()
    assert log == ["init:z", "init:y"]


def test_missing_dependency_raises_and_fails_app() -> None:
    app = Application()
    app.register_component(Recorder("a", ("nope",)))
    with pytest.raises(LifecycleError):
        app.initialize()
    assert app.state is LifecycleState.FAILED


def test_dependency_cycle_raises() -> None:
    app = Application()
    app.register_component(Recorder("a", ("b",)))
    app.register_component(Recorder("b", ("a",)))
    with pytest.raises(LifecycleError):
        app.initialize()
    assert app.state is LifecycleState.FAILED


def test_component_init_failure_transitions_to_failed() -> None:
    class Boom:
        component_name = "boom"
        depends_on: tuple[str, ...] = ()

        def initialize(self) -> None:
            raise RuntimeError("kaboom")

        def shutdown(self) -> None:
            pass

    app = Application()
    app.register_component(Boom())
    with pytest.raises(LifecycleError):
        app.initialize()
    assert app.state is LifecycleState.FAILED


def test_hooks_fire_in_order() -> None:
    log: list[str] = []
    app = Application()
    app.on_pre_init(lambda _: log.append("pre_init"))
    app.on_post_init(lambda _: log.append("post_init"))
    app.on_pre_shutdown(lambda _: log.append("pre_shutdown"))
    app.on_post_shutdown(lambda _: log.append("post_shutdown"))
    app.initialize()
    app.shutdown()
    assert log == ["pre_init", "post_init", "pre_shutdown", "post_shutdown"]


def test_shutdown_is_best_effort_across_failing_component() -> None:
    log: list[str] = []

    class BadStop:
        component_name = "bad"
        depends_on: tuple[str, ...] = ("good",)

        def initialize(self) -> None:
            log.append("init:bad")

        def shutdown(self) -> None:
            raise RuntimeError("stop failed")

    app = Application()
    app.register_component(BadStop())
    app.register_component(Recorder("good", (), log))
    app.initialize()
    app.shutdown()
    # "good" still shut down despite "bad" raising, and app reached STOPPED.
    assert "stop:good" in log
    assert app.state is LifecycleState.STOPPED


def test_register_after_initialize_rejected() -> None:
    app = Application()
    app.initialize()
    with pytest.raises(LifecycleError):
        app.register_component(Recorder("late"))


def test_double_initialize_rejected() -> None:
    app = Application()
    app.initialize()
    with pytest.raises(LifecycleError):
        app.initialize()


def test_shutdown_from_created_rejected() -> None:
    app = Application()
    with pytest.raises(LifecycleError):
        app.shutdown()


def test_component_without_name_rejected() -> None:
    app = Application()
    with pytest.raises(LifecycleError):
        app.register_component(object())


def test_state_change_events_published() -> None:
    seen: list[str] = []
    app = Application()
    app.events.subscribe(
        "substrate.lifecycle.state_changed",
        lambda e: seen.append(e.payload.value),
    )
    app.initialize()
    app.shutdown()
    assert seen == ["initializing", "ready", "shutting_down", "stopped"]


def test_component_lifecycle_events_published() -> None:
    seen: list[str] = []
    app = Application()
    app.events.subscribe(
        "substrate.lifecycle.component_initialized",
        lambda e: seen.append(e.payload),
    )
    app.register_component(Recorder("a"))
    app.initialize()
    assert seen == ["a"]
