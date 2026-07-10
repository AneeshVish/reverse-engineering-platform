"""Substrate tests: execution context and propagation."""

from __future__ import annotations

import threading

import pytest
from reveng_core_substrate import (
    ContextError,
    ExecutionContext,
    current_context,
    new_context,
    use_context,
)


def test_new_context_generates_correlation_id() -> None:
    ctx = new_context()
    assert ctx.correlation_id


def test_new_context_accepts_explicit_id_and_values() -> None:
    ctx = new_context("abc", user="alice")
    assert ctx.correlation_id == "abc"
    assert ctx.get("user") == "alice"
    assert ctx.get("missing", "default") == "default"


def test_with_value_is_immutable_derivation() -> None:
    base = new_context("id")
    derived = base.with_value("k", 1)
    assert base.get("k") is None
    assert derived.get("k") == 1
    assert derived.correlation_id == "id"
    assert isinstance(derived, ExecutionContext)


def test_current_context_without_binding_raises() -> None:
    with pytest.raises(ContextError):
        current_context()


def test_use_context_binds_and_restores() -> None:
    ctx = new_context("outer")
    with use_context(ctx):
        assert current_context().correlation_id == "outer"
    with pytest.raises(ContextError):
        current_context()


def test_nested_contexts_restore_previous() -> None:
    outer = new_context("outer")
    inner = new_context("inner")
    with use_context(outer):
        with use_context(inner):
            assert current_context().correlation_id == "inner"
        assert current_context().correlation_id == "outer"


def test_context_restored_after_exception() -> None:
    outer = new_context("outer")
    with use_context(outer):
        with pytest.raises(RuntimeError), use_context(new_context("inner")):
            raise RuntimeError("boom")
        assert current_context().correlation_id == "outer"


def test_context_is_isolated_per_thread() -> None:
    results: dict[str, object] = {}

    def worker() -> None:
        try:
            current_context()
        except ContextError:
            results["thread"] = "unbound"

    with use_context(new_context("main")):
        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert current_context().correlation_id == "main"

    # The child thread never inherited the main thread's bound context.
    assert results["thread"] == "unbound"
