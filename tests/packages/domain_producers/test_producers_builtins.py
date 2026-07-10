"""Domain-producer tests: reference producers produce normalized artifacts."""

from __future__ import annotations

import pytest
from reveng_domain_producers import (
    ArtifactType,
    ProducerRegistry,
    ProducerRequest,
    register_builtin_producers,
)
from reveng_domain_producers.producers import REFERENCE_PRODUCER_TYPES

# Representative valid inputs per producer name.
VALID_INPUTS = {
    "pe": (b"MZ\x90\x00rest", "exe"),
    "elf": (b"\x7fELFrest", "so"),
    "macho": (b"\xfe\xed\xfa\xcf" + b"\x00" * 8, "dylib"),
    "dex": (b"dex\n035\x00rest", "dex"),
    "apk": (b"PK\x03\x04rest", "apk"),
    "ipa": (b"PK\x03\x04rest", "ipa"),
    "jar": (b"PK\x03\x04rest", "jar"),
    "dotnet": (b"MZ\x90\x00rest", "dll"),
    "firmware": (b"\x00\x01firmwarebytes", "firmware"),
    "memory_image": (b"\x00memdump", "img"),
    "source_project": (b"sourcearchive", "tar"),
    "raw_binary": (b"random bytes", None),
}


def test_reference_set_has_twelve_producers() -> None:
    assert len(REFERENCE_PRODUCER_TYPES) == 12
    names = {cls().name for cls in REFERENCE_PRODUCER_TYPES}
    assert names == set(VALID_INPUTS)


@pytest.mark.parametrize("cls", REFERENCE_PRODUCER_TYPES, ids=lambda c: c().name)
def test_producer_metadata_and_produce(cls) -> None:
    producer = cls()
    content, ext = VALID_INPUTS[producer.name]
    req = ProducerRequest(content=content, source_ref=f"{producer.name}.bin", hint_extension=ext)

    assert producer.version
    assert producer.artifact_type is not ArtifactType.UNKNOWN
    assert producer.validate(req)

    result = producer.produce(req)
    art = result.artifact
    assert art.artifact_type is producer.artifact_type
    assert art.producer == producer.name
    # Normalized output only — no analysis fields leaked in.
    assert set(art.metadata) == {"declared_type", "byte_length"}
    assert art.metadata["byte_length"] == len(content)
    assert art.capabilities == producer.capability_names


@pytest.mark.parametrize("cls", REFERENCE_PRODUCER_TYPES, ids=lambda c: c().name)
def test_producer_capabilities_descriptor(cls) -> None:
    producer = cls()
    caps = producer.supported_capabilities()
    assert caps.names() == producer.capability_names


def test_manager_end_to_end_for_each_type() -> None:
    reg = ProducerRegistry()
    register_builtin_producers(reg)
    from reveng_domain_producers import ProducerManager

    mgr = ProducerManager(reg)
    for name, (content, ext) in VALID_INPUTS.items():
        art = mgr.produce(ProducerRequest(content=content, source_ref=name, hint_extension=ext))
        assert art.producer  # a producer was selected and produced
