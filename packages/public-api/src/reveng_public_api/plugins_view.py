"""Read-only plugin-API exposure.

Reflects the plugin SDK's registry over HTTP without mutating it or invoking
any plugin -- listing only, per the plugin framework's passive-plugin
invariant.
"""

from __future__ import annotations

from reveng_plugin_sdk import PluginManager

from .schemas import PluginSummary

__all__ = ["list_plugins"]


def list_plugins(manager: PluginManager) -> tuple[PluginSummary, ...]:
    summaries = []
    for plugin in manager.registry.all():
        meta = plugin.metadata()
        summaries.append(
            PluginSummary(
                identifier=meta.identifier,
                name=meta.name,
                capabilities=list(meta.capability_names()),
            )
        )
    return tuple(summaries)
