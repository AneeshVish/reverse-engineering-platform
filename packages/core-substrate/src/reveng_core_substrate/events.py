"""Substrate-internal synchronous event dispatch.

A minimal in-process publish/subscribe mechanism for lifecycle and
infrastructure signals. Dispatch is synchronous and deterministic: subscribers
to a topic are invoked in subscription order. A failing subscriber does not
abort the dispatch or propagate to the publisher; its failure is collected and
surfaced through the dispatcher's error sink so one bad handler cannot destabilize
the substrate.

This is an internal signal bus, not the platform communication/event system
owned by later Implementation Specifications.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from reveng_errors import EngError, err

__all__ = ["Event", "Subscriber", "EventDispatcher"]


@dataclass(frozen=True)
class Event:
    """An immutable named signal with an arbitrary payload."""

    topic: str
    payload: Any = None


Subscriber = Callable[[Event], None]


class EventDispatcher:
    """Synchronous, deterministic, failure-isolating event bus."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subscribers: dict[str, list[Subscriber]] = {}

    def subscribe(self, topic: str, subscriber: Subscriber) -> None:
        with self._lock:
            self._subscribers.setdefault(topic, []).append(subscriber)

    def unsubscribe(self, topic: str, subscriber: Subscriber) -> None:
        with self._lock:
            handlers = self._subscribers.get(topic)
            if handlers and subscriber in handlers:
                handlers.remove(subscriber)

    def publish(self, event: Event) -> list[EngError]:
        """Deliver ``event`` to subscribers in order.

        Returns the list of errors raised by individual subscribers (empty when
        all succeeded). The publisher is never interrupted by a subscriber
        failure.
        """

        with self._lock:
            handlers = list(self._subscribers.get(event.topic, ()))

        errors: list[EngError] = []
        for handler in handlers:
            try:
                handler(event)
            except Exception as exc:  # noqa: BLE001 - deliberate isolation boundary
                errors.append(
                    err(
                        "SUBSTRATE.EVENT.SUBSCRIBER",
                        str(exc),
                        topic=event.topic,
                        exception_type=type(exc).__name__,
                    )
                )
        return errors

    def topics(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._subscribers))
