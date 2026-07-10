"""Substrate tests: registries."""

from __future__ import annotations

import pytest
from reveng_core_substrate import (
    CapabilityRegistry,
    ComponentRegistry,
    ExtensionRegistry,
    FeatureRegistry,
    RegistryError,
)


def test_keyed_registry_registration_order() -> None:
    r = ComponentRegistry()
    r.register("b", 1)
    r.register("a", 2)
    assert r.keys() == ("b", "a")
    assert r.items() == (("b", 1), ("a", 2))
    assert len(r) == 2


def test_keyed_registry_duplicate() -> None:
    r = CapabilityRegistry()
    r.register("x", object())
    with pytest.raises(RegistryError):
        r.register("x", object())


def test_keyed_registry_missing() -> None:
    r = CapabilityRegistry()
    assert not r.contains("x")
    with pytest.raises(RegistryError):
        r.get("x")


def test_feature_registry() -> None:
    f = FeatureRegistry()
    f.register("flag", enabled=False)
    assert not f.is_enabled("flag")
    f.set_enabled("flag", True)
    assert f.is_enabled("flag")
    assert f.names() == ("flag",)


def test_feature_registry_errors() -> None:
    f = FeatureRegistry()
    with pytest.raises(RegistryError):
        f.is_enabled("missing")
    with pytest.raises(RegistryError):
        f.set_enabled("missing", True)
    f.register("a")
    with pytest.raises(RegistryError):
        f.register("a")


def test_extension_registry_ordered_contributions() -> None:
    e = ExtensionRegistry()
    e.register_point("hooks")
    e.contribute("hooks", "first")
    e.contribute("hooks", "second")
    assert e.extensions("hooks") == ("first", "second")
    assert e.points() == ("hooks",)


def test_extension_registry_errors() -> None:
    e = ExtensionRegistry()
    with pytest.raises(RegistryError):
        e.contribute("missing", 1)
    with pytest.raises(RegistryError):
        e.extensions("missing")
    e.register_point("p")
    with pytest.raises(RegistryError):
        e.register_point("p")
