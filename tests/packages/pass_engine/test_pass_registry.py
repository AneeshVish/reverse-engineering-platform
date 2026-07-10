"""Pass-engine tests: registry."""

from __future__ import annotations

import pytest
from _helpers import RecordingPass
from reveng_pass_engine import PassRegistry, RegistrationError


def test_register_and_lookup() -> None:
    reg = PassRegistry()
    reg.register(RecordingPass("a"))
    assert reg.contains("a")
    assert reg.get("a").identifier == "a"
    assert len(reg) == 1


def test_registration_order_preserved() -> None:
    reg = PassRegistry()
    reg.register(RecordingPass("b"))
    reg.register(RecordingPass("a"))
    assert reg.identifiers() == ("b", "a")


def test_duplicate_rejected() -> None:
    reg = PassRegistry()
    reg.register(RecordingPass("a"))
    with pytest.raises(RegistrationError):
        reg.register(RecordingPass("a"))


def test_missing_lookup_raises() -> None:
    reg = PassRegistry()
    with pytest.raises(RegistrationError):
        reg.get("nope")


def test_all_returns_registration_order() -> None:
    reg = PassRegistry()
    for name in ("x", "y", "z"):
        reg.register(RecordingPass(name))
    assert tuple(p.identifier for p in reg.all()) == ("x", "y", "z")
