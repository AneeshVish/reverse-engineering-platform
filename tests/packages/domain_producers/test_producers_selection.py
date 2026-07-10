"""Domain-producer tests: deterministic selection precedence."""

from __future__ import annotations

import pytest
from reveng_domain_producers import (
    ClaimStrength,
    ProducerRegistry,
    ProducerRequest,
    SelectionError,
    register_builtin_producers,
    select_producer,
)
from reveng_domain_producers.producers import PEProducer, RawBinaryProducer


def _registry():
    reg = ProducerRegistry()
    register_builtin_producers(reg)
    return reg


def test_strong_claim_beats_weak_fallback() -> None:
    reg = _registry()
    req = ProducerRequest(content=b"MZ\x90\x00", source_ref="a.exe", hint_extension="exe")
    assert select_producer(reg, req).name == "pe"


def test_raw_binary_is_fallback() -> None:
    reg = _registry()
    req = ProducerRequest(content=b"\x00\x01\x02\x03", source_ref="blob")
    assert select_producer(reg, req).name == "raw_binary"


def test_no_claim_raises() -> None:
    reg = ProducerRegistry()
    reg.register(PEProducer())  # only PE; empty content claims nothing
    with pytest.raises(SelectionError):
        select_producer(reg, ProducerRequest(content=b"", source_ref="x"))


def test_priority_breaks_equal_claim_strength() -> None:
    class HiPE(PEProducer):
        name = "hi_pe"
        priority = 1000  # higher than the default PE producer

    reg = ProducerRegistry()
    reg.register(PEProducer())
    reg.register(HiPE())
    req = ProducerRequest(content=b"MZ\x90\x00", source_ref="a.exe", hint_extension="exe")
    # Both claim STRONG; the higher-priority producer wins regardless of order.
    assert select_producer(reg, req).name == "hi_pe"


def test_registration_order_breaks_equal_priority() -> None:
    class PEa(PEProducer):
        name = "pe_a"

    class PEb(PEProducer):
        name = "pe_b"

    reg = ProducerRegistry()
    reg.register(PEa())
    reg.register(PEb())
    req = ProducerRequest(content=b"MZ\x90\x00", source_ref="a.exe", hint_extension="exe")
    # Equal claim + equal priority → earliest registration wins.
    assert select_producer(reg, req).name == "pe_a"


def test_selection_is_deterministic_across_runs() -> None:
    reg = _registry()
    req = ProducerRequest(content=b"\x7fELF\x02", source_ref="x.so", hint_extension="so")
    picks = {select_producer(reg, req).name for _ in range(5)}
    assert picks == {"elf"}


def test_weak_only_still_selects() -> None:
    reg = ProducerRegistry()
    reg.register(RawBinaryProducer())
    req = ProducerRequest(content=b"anything", source_ref="x")
    assert select_producer(reg, req).identify(req) is ClaimStrength.WEAK
    assert select_producer(reg, req).name == "raw_binary"
