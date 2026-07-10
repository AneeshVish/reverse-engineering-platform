"""Domain-producer tests: error taxonomy and boundary conversion."""

from __future__ import annotations

import pytest
from reveng_domain_producers import (
    IdentificationError,
    ProducerError,
    ProducerManager,
    ProducerRegistry,
    ProducerRequest,
    ProductionError,
    RegistrationError,
    SelectionError,
    ValidationError,
    guard,
    make_error,
    register_builtin_producers,
)


def test_error_codes_namespaced() -> None:
    assert ProducerError.code == "PRODUCER.ERROR"
    assert RegistrationError.code == "PRODUCER.REGISTRATION"
    assert IdentificationError.code == "PRODUCER.IDENTIFICATION"
    assert ValidationError.code == "PRODUCER.VALIDATION"
    assert SelectionError.code == "PRODUCER.SELECTION"
    assert ProductionError.code == "PRODUCER.PRODUCTION"


def test_error_to_eng_error_carries_context() -> None:
    eng = SelectionError("none", source_ref="x").to_eng_error()
    assert eng.code == "PRODUCER.SELECTION"
    assert eng.context["source_ref"] == "x"


def test_make_error() -> None:
    eng = make_error("PRODUCER.X", "m", a=1)
    assert eng.code == "PRODUCER.X"
    assert eng.context["a"] == 1


def test_guard_success() -> None:
    result = guard(lambda: 5)
    assert result.ok and result.value == 5


def test_guard_converts_producer_error() -> None:
    def fail() -> int:
        raise ValidationError("bad", producer="pe")

    result = guard(fail)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PRODUCER.VALIDATION"


def test_guard_converts_unexpected() -> None:
    result = guard(lambda: 1 / 0)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PRODUCER.UNEXPECTED"
    assert result.error.context["exception_type"] == "ZeroDivisionError"


def test_no_producer_claim_surfaces_via_guard() -> None:
    mgr = ProducerManager(ProducerRegistry())  # empty registry
    result = guard(lambda: mgr.produce(ProducerRequest(content=b"x", source_ref="r")))
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "PRODUCER.SELECTION"


def test_validation_failure_raises_producer_error() -> None:
    reg = ProducerRegistry()
    register_builtin_producers(reg)
    mgr = ProducerManager(reg)

    # A custom high-priority producer that claims but fails validation.
    from reveng_domain_producers import ClaimStrength
    from reveng_domain_producers.producers import RawBinaryProducer

    class Picky(RawBinaryProducer):
        name = "picky"
        priority = 10_000

        def identify(self, request):
            return ClaimStrength.STRONG

        def validate(self, request):
            return False

    reg.register(Picky())
    with pytest.raises(ValidationError):
        mgr.produce(ProducerRequest(content=b"anything", source_ref="r"))
