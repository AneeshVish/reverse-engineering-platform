"""Plugin tests: validation, loading, and error boundary."""

from __future__ import annotations

import pytest
from _plugin_helpers import MockPlugin, chain
from reveng_plugin_sdk import (
    DependencyError,
    LoadingError,
    PluginLoader,
    PluginRegistry,
    PluginValidator,
    ValidationError,
    guard,
    make_error,
    validate_plugin,
    validate_plugins,
)


def test_validate_ok() -> None:
    validate_plugin(MockPlugin("a"))
    validate_plugins(chain())


def test_validate_rejects_empty_identifier() -> None:
    with pytest.raises(ValidationError):
        validate_plugin(MockPlugin(""))


def test_validate_rejects_duplicates() -> None:
    with pytest.raises(ValidationError):
        validate_plugins((MockPlugin("a"), MockPlugin("a")))


def test_validate_delegates_missing_dependency() -> None:
    with pytest.raises(DependencyError):
        validate_plugins((MockPlugin("a", dependencies=("ghost",)),))


def test_validator_wrapper() -> None:
    PluginValidator().validate(chain())


def test_loader_registers_in_load_order() -> None:
    reg = PluginRegistry()
    order = PluginLoader().load(chain(), reg)
    assert order == ("a", "b", "c")
    assert reg.identifiers() == ("a", "b", "c")


def test_loader_rejects_invalid_metadata() -> None:
    reg = PluginRegistry()
    with pytest.raises(ValidationError):
        PluginLoader().load((MockPlugin(""),), reg)


def test_loader_wraps_registration_conflict_as_loading_error() -> None:
    reg = PluginRegistry()
    PluginLoader().load((MockPlugin("a"),), reg)
    with pytest.raises(LoadingError):
        PluginLoader().load((MockPlugin("a"),), reg)


def test_guard_captures_plugin_error() -> None:
    def boom() -> int:
        raise ValidationError("bad", plugin="p")

    result = guard(boom)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PLUGIN.VALIDATION"


def test_guard_captures_unexpected() -> None:
    def boom() -> int:
        raise KeyError("x")

    result = guard(boom)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PLUGIN.UNEXPECTED"


def test_guard_passes_success() -> None:
    result = guard(lambda: 42)
    assert result.ok
    assert result.value == 42


def test_make_error_uses_code() -> None:
    error = make_error("PLUGIN.TEST", "boom")
    assert error.code == "PLUGIN.TEST"
