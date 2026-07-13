"""Typed, immutable evidence metadata with deterministic ordering.

A ``MetadataBag`` is an immutable mapping from string keys to scalar values.
Iteration and serialization are always key-sorted so equal metadata produces
identical output regardless of insertion order. This is storage-owned, keeping
evidence metadata independent of the IR representation's metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Union

__all__ = ["MetadataKey", "MetadataValue", "MetadataBag", "EMPTY_METADATA"]

MetadataKey = str
MetadataValue = Union[str, int, float, bool]


@dataclass(frozen=True)
class MetadataBag:
    """An immutable, deterministically-ordered scalar metadata map."""

    _items: tuple[tuple[str, MetadataValue], ...] = ()

    @classmethod
    def of(cls, mapping: dict[str, MetadataValue] | None = None) -> MetadataBag:
        if not mapping:
            return cls(())
        return cls(tuple(sorted(mapping.items())))

    def get(self, key: str, default: MetadataValue | None = None) -> MetadataValue | None:
        for k, v in self._items:
            if k == key:
                return v
        return default

    def contains(self, key: str) -> bool:
        return any(k == key for k, _ in self._items)

    def with_value(self, key: str, value: MetadataValue) -> MetadataBag:
        merged = {k: v for k, v in self._items}
        merged[key] = value
        return MetadataBag.of(merged)

    def as_mapping(self) -> MappingProxyType[str, MetadataValue]:
        return MappingProxyType(dict(self._items))

    def items(self) -> tuple[tuple[str, MetadataValue], ...]:
        """Key-sorted (key, value) pairs."""

        return self._items

    def keys(self) -> tuple[str, ...]:
        return tuple(k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)


EMPTY_METADATA = MetadataBag(())
