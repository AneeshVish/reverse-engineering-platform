"""Canonical, deterministic plugin metadata serialization.

Serializes ``PluginMetadata`` (metadata only — never executable code) to canonical
JSON: capabilities sorted, object keys sorted. The same metadata always serializes
to identical bytes, and a round-trip reproduces equal metadata.
"""

from __future__ import annotations

import json
from typing import Any

from .capabilities import CapabilityDescriptor, CapabilityKind, ExtensionPoint
from .errors import ValidationError
from .metadata import PluginMetadata

__all__ = ["MetadataSerializer", "MetadataDeserializer"]


def _enc_capability(c: CapabilityDescriptor) -> dict[str, Any]:
    return {
        "kind": c.kind.value,
        "extension_point": c.extension_point.value,
        "name": c.name,
        "description": c.description,
    }


def _dec_capability(raw: Any) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        kind=CapabilityKind(raw["kind"]),
        extension_point=ExtensionPoint(raw["extension_point"]),
        name=raw["name"],
        description=raw.get("description", ""),
    )


class MetadataSerializer:
    """Serializes ``PluginMetadata`` to canonical JSON text."""

    def serialize(self, meta: PluginMetadata) -> str:
        caps = sorted((_enc_capability(c) for c in meta.capabilities), key=lambda d: d["name"])
        payload = {
            "identifier": meta.identifier,
            "name": meta.name,
            "version": meta.version,
            "author": meta.author,
            "description": meta.description,
            "capabilities": caps,
            "dependencies": sorted(meta.dependencies),
            "priority": meta.priority,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class MetadataDeserializer:
    """Reconstructs ``PluginMetadata`` from canonical JSON text."""

    def deserialize(self, data: str) -> PluginMetadata:
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValidationError("invalid plugin metadata", detail=str(exc)) from exc
        return PluginMetadata(
            identifier=payload["identifier"],
            name=payload.get("name", ""),
            version=payload.get("version", "1.0.0"),
            author=payload.get("author", ""),
            description=payload.get("description", ""),
            capabilities=tuple(_dec_capability(c) for c in payload.get("capabilities", [])),
            dependencies=tuple(payload.get("dependencies", [])),
            priority=payload.get("priority", 100),
        )
