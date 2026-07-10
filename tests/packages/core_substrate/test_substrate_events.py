"""Substrate tests: internal event dispatch."""

from __future__ import annotations

from reveng_core_substrate import Event, EventDispatcher


def test_subscribers_invoked_in_subscription_order() -> None:
    seen: list[str] = []
    d = EventDispatcher()
    d.subscribe("t", lambda _: seen.append("first"))
    d.subscribe("t", lambda _: seen.append("second"))
    errors = d.publish(Event("t"))
    assert seen == ["first", "second"]
    assert errors == []


def test_payload_delivered() -> None:
    seen: list[object] = []
    d = EventDispatcher()
    d.subscribe("t", lambda e: seen.append(e.payload))
    d.publish(Event("t", payload={"k": 1}))
    assert seen == [{"k": 1}]


def test_publish_to_unknown_topic_is_noop() -> None:
    d = EventDispatcher()
    assert d.publish(Event("nobody-listening")) == []


def test_failing_subscriber_is_isolated() -> None:
    seen: list[str] = []
    d = EventDispatcher()

    def bad(_: Event) -> None:
        raise RuntimeError("handler failed")

    d.subscribe("t", bad)
    d.subscribe("t", lambda _: seen.append("still ran"))

    errors = d.publish(Event("t"))

    # The publisher was never interrupted; the later subscriber still ran.
    assert seen == ["still ran"]
    assert len(errors) == 1
    assert errors[0].code == "SUBSTRATE.EVENT.SUBSCRIBER"
    assert errors[0].context["topic"] == "t"
    assert errors[0].context["exception_type"] == "RuntimeError"


def test_unsubscribe() -> None:
    seen: list[str] = []
    d = EventDispatcher()

    def handler(_: Event) -> None:
        seen.append("x")

    d.subscribe("t", handler)
    d.unsubscribe("t", handler)
    d.publish(Event("t"))
    assert seen == []


def test_unsubscribe_unknown_is_safe() -> None:
    d = EventDispatcher()
    d.unsubscribe("t", lambda _: None)  # no raise


def test_topics_sorted() -> None:
    d = EventDispatcher()
    d.subscribe("z", lambda _: None)
    d.subscribe("a", lambda _: None)
    assert d.topics() == ("a", "z")
