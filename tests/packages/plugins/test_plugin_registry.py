"""Plugin tests: registry."""

from __future__ import annotations

import pytest
from _plugin_helpers import MockPlugin
from reveng_plugin_sdk import PluginRegistry, RegistrationError


def test_register_and_lookup() -> None:
    reg = PluginRegistry()
    reg.register(MockPlugin("a"))
    assert reg.contains("a")
    assert reg.get("a").identifier == "a"
    assert len(reg) == 1


def test_registration_order_preserved() -> None:
    reg = PluginRegistry()
    reg.register(MockPlugin("b"))
    reg.register(MockPlugin("a"))
    assert reg.identifiers() == ("b", "a")


def test_duplicate_rejected() -> None:
    reg = PluginRegistry()
    reg.register(MockPlugin("a"))
    with pytest.raises(RegistrationError):
        reg.register(MockPlugin("a"))


def test_missing_lookup_raises() -> None:
    reg = PluginRegistry()
    with pytest.raises(RegistrationError):
        reg.get("nope")


def test_all_returns_registration_order() -> None:
    reg = PluginRegistry()
    for name in ("x", "y", "z"):
        reg.register(MockPlugin(name))
    assert tuple(p.identifier for p in reg.all()) == ("x", "y", "z")
