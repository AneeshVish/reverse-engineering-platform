"""Plugin tests: metadata, capabilities, and serialization."""

from __future__ import annotations

import dataclasses

import pytest
from _plugin_helpers import MockPlugin
from reveng_plugin_sdk import (
    CapabilityDescriptor,
    CapabilityKind,
    ExtensionPoint,
    MetadataDeserializer,
    MetadataSerializer,
    PluginMetadata,
    ValidationError,
)


def test_metadata_is_immutable() -> None:
    meta = PluginMetadata(identifier="p")
    with pytest.raises(dataclasses.FrozenInstanceError):
        meta.identifier = "q"  # type: ignore[misc]


def test_capability_is_immutable() -> None:
    cap = CapabilityDescriptor(CapabilityKind.PRODUCER, ExtensionPoint.PRODUCER_REGISTRY, "c")
    with pytest.raises(dataclasses.FrozenInstanceError):
        cap.name = "x"  # type: ignore[misc]


def test_capability_helpers() -> None:
    meta = MockPlugin("p", capability_names=("z", "a")).metadata()
    assert meta.capability_names() == ("a", "z")


def test_serialization_is_deterministic() -> None:
    meta = MockPlugin("p", capability_names=("b", "a"), dependencies=("d2", "d1")).metadata()
    ser = MetadataSerializer()
    assert ser.serialize(meta) == ser.serialize(meta)


def test_serialization_round_trip() -> None:
    meta = MockPlugin("p", capability_names=("cap",), dependencies=("dep",)).metadata()
    data = MetadataSerializer().serialize(meta)
    restored = MetadataDeserializer().deserialize(data)
    assert MetadataSerializer().serialize(restored) == data


def test_serialization_order_independent() -> None:
    a = MockPlugin("p", capability_names=("b", "a")).metadata()
    b = MockPlugin("p", capability_names=("a", "b")).metadata()
    assert MetadataSerializer().serialize(a) == MetadataSerializer().serialize(b)


def test_invalid_metadata_document_raises() -> None:
    with pytest.raises(ValidationError):
        MetadataDeserializer().deserialize("{not json")


def test_no_timestamp_in_output() -> None:
    data = MetadataSerializer().serialize(MockPlugin("p").metadata())
    for banned in ("timestamp", "created", "generated_at"):
        assert banned not in data
