"""Producer selection.

Given a request, poll every registered producer's claim and pick a winner with a
fully deterministic ordering:

    1. highest ``ClaimStrength``
    2. highest ``priority``
    3. earliest registration order

Because registration order alone is unstable across environments, priority is the
stable override lever: a third-party producer beats a built-in for the same source
simply by declaring a higher priority.
"""

from __future__ import annotations

from .contracts import ClaimStrength, Producer, ProducerRequest
from .errors import SelectionError
from .registry import ProducerRegistry

__all__ = ["select_producer"]


def select_producer(registry: ProducerRegistry, request: ProducerRequest) -> Producer:
    """Return the winning producer for ``request``.

    Raises ``SelectionError`` if no producer issues a claim stronger than NONE.
    """

    best: Producer | None = None
    best_key: tuple[int, int, int] | None = None

    for order, producer in enumerate(registry.all()):
        strength = producer.identify(request)
        if strength <= ClaimStrength.NONE:
            continue
        # Negate order so that, under max(), an earlier registration wins ties.
        key = (int(strength), producer.priority, -order)
        if best_key is None or key > best_key:
            best_key = key
            best = producer

    if best is None:
        raise SelectionError("no producer claimed the source", source_ref=request.source_ref)
    return best
