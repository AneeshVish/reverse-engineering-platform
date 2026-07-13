"""Plugin validation.

Structural only: duplicate identifiers, dependency cycles, missing dependencies,
and invalid capability declarations. Cycle and missing-dependency detection reuses
the dependency resolver so there is a single ordering algorithm.
"""

from __future__ import annotations

from collections.abc import Sequence

from .dependency import resolve_load_order
from .errors import ValidationError
from .plugin import Plugin

__all__ = ["validate_plugin", "validate_plugins", "PluginValidator"]


def validate_plugin(plugin: Plugin) -> None:
    """Validate a single plugin's metadata, raising ``ValidationError``."""

    meta = plugin.metadata()
    if not meta.identifier:
        raise ValidationError("plugin has no identifier")
    if not meta.version:
        raise ValidationError("plugin has no version", plugin=meta.identifier)
    for capability in meta.capabilities:
        if not capability.name:
            raise ValidationError("capability has no name", plugin=meta.identifier)


def validate_plugins(plugins: Sequence[Plugin]) -> None:
    """Validate a collection of plugins as a whole."""

    seen: set[str] = set()
    for plugin in plugins:
        validate_plugin(plugin)
        identifier = plugin.metadata().identifier
        if identifier in seen:
            raise ValidationError("duplicate plugin id", plugin=identifier)
        seen.add(identifier)

    # Delegates missing-dependency and cycle detection to the single resolver.
    resolve_load_order(plugins)


class PluginValidator:
    """Object wrapper around the validation functions."""

    def validate(self, plugins: Sequence[Plugin]) -> None:
        validate_plugins(plugins)
