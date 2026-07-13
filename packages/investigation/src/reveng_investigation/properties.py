"""Immutable, key-sorted investigation properties.

A ``PropertyBag`` is an immutable mapping from string keys to scalar values,
always key-sorted so equal properties produce identical output regardless of
insertion order.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Union

__all__ = ["PropertyKey", "PropertyValue", "PropertyBag", "EMPTY_PROPERTIES"]

PropertyKey = str
PropertyValue = Union[str, int, float, bool]


@dataclass(frozen=True)
class PropertyBag:
    """An immutable, deterministically-ordered scalar property map."""

    _items: tuple[tuple[str, PropertyValue], ...] = ()

    @classmethod
    def of(cls, mapping: dict[str, PropertyValue] | None = None) -> PropertyBag:
        if not mapping:
            return cls(())
        return cls(tuple(sorted(mapping.items())))

    def get(self, key: str, default: PropertyValue | None = None) -> PropertyValue | None:
        for k, v in self._items:
            if k == key:
                return v
        return default

    def contains(self, key: str) -> bool:
        return any(k == key for k, _ in self._items)

    def as_mapping(self) -> MappingProxyType[str, PropertyValue]:
        return MappingProxyType(dict(self._items))

    def items(self) -> tuple[tuple[str, PropertyValue], ...]:
        """Key-sorted (key, value) pairs."""

        return self._items

    def keys(self) -> tuple[str, ...]:
        return tuple(k for k, _ in self._items)

    def __len__(self) -> int:
        return len(self._items)


EMPTY_PROPERTIES = PropertyBag(())
