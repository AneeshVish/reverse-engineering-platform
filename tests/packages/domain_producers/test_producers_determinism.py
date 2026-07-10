"""Domain-producer tests: purity and determinism."""

from __future__ import annotations

import time

from reveng_domain_producers import (
    ProducerManager,
    ProducerRegistry,
    ProducerRequest,
    register_builtin_producers,
)


def _manager() -> ProducerManager:
    reg = ProducerRegistry()
    register_builtin_producers(reg)
    return ProducerManager(reg)


def test_identical_input_yields_identical_artifact() -> None:
    mgr = _manager()
    req = ProducerRequest(content=b"MZ\x90\x00payload", source_ref="a.exe", hint_extension="exe")
    first = mgr.produce(req)
    second = mgr.produce(req)
    assert first == second
    assert first.identity == second.identity
    assert dict(first.metadata) == dict(second.metadata)
    assert first.provenance == second.provenance


def test_production_is_time_independent() -> None:
    mgr = _manager()
    req = ProducerRequest(content=b"\x7fELFpayload", source_ref="x.so", hint_extension="so")
    first = mgr.produce(req)
    time.sleep(0.01)
    second = mgr.produce(req)
    # No wall-clock or machine value leaks into identity or provenance.
    assert first == second


def test_two_registries_agree() -> None:
    req = ProducerRequest(content=b"dex\n035\x00zz", source_ref="c.dex", hint_extension="dex")
    a = _manager().produce(req)
    b = _manager().produce(req)
    assert a == b
