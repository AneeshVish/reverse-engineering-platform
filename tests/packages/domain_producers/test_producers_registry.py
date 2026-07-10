"""Domain-producer tests: registry and factory."""

from __future__ import annotations

import pytest
from reveng_domain_producers import (
    ClaimStrength,
    ProducerFactory,
    ProducerRegistry,
    RegistrationError,
)
from reveng_domain_producers.producers import PEProducer, RawBinaryProducer


def test_register_and_lookup() -> None:
    reg = ProducerRegistry()
    reg.register(PEProducer())
    assert reg.contains("pe")
    assert isinstance(reg.get("pe"), PEProducer)
    assert len(reg) == 1


def test_registration_order_preserved() -> None:
    reg = ProducerRegistry()
    reg.register(RawBinaryProducer())
    reg.register(PEProducer())
    assert reg.names() == ("raw_binary", "pe")


def test_duplicate_rejected() -> None:
    reg = ProducerRegistry()
    reg.register(PEProducer())
    with pytest.raises(RegistrationError):
        reg.register(PEProducer())


def test_missing_lookup_raises() -> None:
    reg = ProducerRegistry()
    with pytest.raises(RegistrationError):
        reg.get("nope")


def test_factory_validates_type() -> None:
    reg = ProducerRegistry()
    factory = ProducerFactory(reg)
    with pytest.raises(RegistrationError):
        factory.register(object())  # type: ignore[arg-type]


def test_factory_rejects_nameless_producer() -> None:
    class Nameless(RawBinaryProducer):
        name = ""

    reg = ProducerRegistry()
    factory = ProducerFactory(reg)
    with pytest.raises(RegistrationError):
        factory.register(Nameless())


def test_third_party_producer_registers_equally() -> None:
    class CustomProducer(RawBinaryProducer):
        name = "custom"

        def identify(self, request):
            if request.content.startswith(b"CUST"):
                return ClaimStrength.STRONG
            return ClaimStrength.NONE

    reg = ProducerRegistry()
    factory = ProducerFactory(reg)
    factory.register(CustomProducer())
    assert "custom" in reg.names()
