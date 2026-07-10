"""Substrate tests: dependency-injection container."""

from __future__ import annotations

import threading

import pytest
from reveng_core_substrate import ContainerError, ServiceContainer


def test_register_and_resolve_instance() -> None:
    c = ServiceContainer()
    c.register_instance("cfg", {"a": 1})
    assert c.resolve("cfg") == {"a": 1}
    assert c.is_registered("cfg")


def test_singleton_built_once() -> None:
    c = ServiceContainer()
    calls = []

    def factory(_: ServiceContainer) -> object:
        calls.append(1)
        return object()

    c.register_singleton("svc", factory)
    first = c.resolve("svc")
    second = c.resolve("svc")
    assert first is second
    assert len(calls) == 1


def test_factory_built_each_time() -> None:
    c = ServiceContainer()
    c.register_factory("svc", lambda _: object())
    assert c.resolve("svc") is not c.resolve("svc")


def test_factory_can_resolve_dependencies() -> None:
    c = ServiceContainer()
    c.register_instance("dep", 10)
    c.register_factory("svc", lambda cont: cont.resolve("dep") + 1)
    assert c.resolve("svc") == 11


def test_missing_registration_raises() -> None:
    c = ServiceContainer()
    with pytest.raises(ContainerError):
        c.resolve("nope")


def test_duplicate_registration_raises() -> None:
    c = ServiceContainer()
    c.register_instance("x", 1)
    with pytest.raises(ContainerError):
        c.register_instance("x", 2)


def test_cycle_detected() -> None:
    c = ServiceContainer()
    c.register_singleton("a", lambda cont: cont.resolve("b"))
    c.register_singleton("b", lambda cont: cont.resolve("a"))
    with pytest.raises(ContainerError):
        c.resolve("a")


def test_keys_sorted() -> None:
    c = ServiceContainer()
    c.register_instance("z", 1)
    c.register_instance("a", 1)
    assert c.keys() == ("a", "z")


def test_concurrent_singleton_single_construction() -> None:
    c = ServiceContainer()
    calls: list[int] = []

    def factory(_: ServiceContainer) -> object:
        calls.append(1)
        return object()

    c.register_singleton("svc", factory)
    results: list[object] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        results.append(c.resolve("svc"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1
    assert all(r is results[0] for r in results)
