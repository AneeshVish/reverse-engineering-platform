# -*- coding: utf-8 -*-
"""Pluggable search providers (Phase 016 spec, 10.7).

The command palette's matching engine is a small provider interface rather
than one hardcoded action list. Phase 016 enables exactly four providers
(``CommandProvider``, ``FunctionProvider``, ``ReportProvider``,
``ExtensionProvider``); later phases add more (``EvidenceProvider``,
``GraphNodeProvider``, ...) as pure additions -- the registry and the
palette UI never need to change.

Ranking (10.7): every provider returns ``(score, display_text, type,
navigation_callback)`` results; the registry merges by score, preserving
each provider's own ordering among ties rather than imposing a global
tiebreak.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol


@dataclass(frozen=True)
class SearchResult:
    score: float
    display_text: str
    result_type: str
    callback: Callable[[], None]


class SearchProvider(Protocol):
    def search(self, query: str) -> list[SearchResult]: ...


def fuzzy_score(query: str, label: str) -> Optional[float]:
    """Shared scoring so every provider ranks consistently: exact > prefix >
    substring > subsequence. Returns None on no match at all."""

    if not query:
        return 10.0
    q = query.lower()
    text = label.lower()
    if q == text:
        return 100.0
    if text.startswith(q):
        return 80.0
    if q in text:
        return 60.0
    it = iter(text)
    if all(ch in it for ch in q):
        return 40.0
    return None


class CommandProvider:
    """Wraps the app's existing fixed action list (today's ~17 commands)."""

    def __init__(self, actions: list[tuple[str, Callable[[], None]]]) -> None:
        self._actions = list(actions)

    def search(self, query: str) -> list[SearchResult]:
        results = []
        for label, callback in self._actions:
            score = fuzzy_score(query, label)
            if score is not None:
                results.append(SearchResult(score, label, "Command", callback))
        return results


class FunctionProvider:
    """Function names/addresses already loaded in the Functions tree."""

    def __init__(
        self,
        get_functions: Callable[[], list[tuple[str, int]]],
        navigate: Callable[[int], None],
    ) -> None:
        self._get_functions = get_functions
        self._navigate = navigate

    def search(self, query: str) -> list[SearchResult]:
        results = []
        for name, address in self._get_functions():
            score = fuzzy_score(query, name)
            if score is not None:
                label = f"{name}  @ 0x{address:x}"
                results.append(
                    SearchResult(score, label, "Function", lambda a=address: self._navigate(a))
                )
        return results


class ReportProvider:
    """Substring match over the current Report's rendered text."""

    def __init__(self, get_report_text: Callable[[], Optional[str]], open_report: Callable[[], None]) -> None:
        self._get_report_text = get_report_text
        self._open_report = open_report

    def search(self, query: str) -> list[SearchResult]:
        if not query:
            return []
        text = self._get_report_text()
        if not text or query.lower() not in text.lower():
            return []
        idx = text.lower().index(query.lower())
        snippet = text[max(0, idx - 20) : idx + 40].replace("\n", " ")
        return [SearchResult(55.0, f"Report: …{snippet}…", "Report", self._open_report)]


class ExtensionProvider:
    """Matches over the Extensions (plugins) list."""

    def __init__(self, get_extensions: Callable[[], list], open_extensions: Callable[[], None]) -> None:
        self._get_extensions = get_extensions
        self._open_extensions = open_extensions

    def search(self, query: str) -> list[SearchResult]:
        results = []
        for ext in self._get_extensions():
            score = fuzzy_score(query, ext.name)
            if score is not None:
                results.append(
                    SearchResult(score, f"Extension: {ext.name}", "Extension", self._open_extensions)
                )
        return results


class SearchProviderRegistry:
    """Queries every registered provider and merges results by score."""

    def __init__(self) -> None:
        self._providers: list[SearchProvider] = []

    def register(self, provider: SearchProvider) -> None:
        self._providers.append(provider)

    def search(self, query: str) -> list[SearchResult]:
        merged: list[SearchResult] = []
        for provider in self._providers:
            merged.extend(provider.search(query))
        # Stable sort: score descending, preserving each provider's own
        # relative order (and provider registration order) among ties.
        merged.sort(key=lambda r: r.score, reverse=True)
        return merged
