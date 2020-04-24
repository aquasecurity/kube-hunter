import pytest

from kube_hunter.core.events.subscription import Subscription, subscribe, subscribe_once
from kube_hunter.core.events.types import Event


class SomeEvent(Event):
    pass


def test_subscribe_default_values():
    @subscribe(SomeEvent)
    class SomeSubscriber:
        pass

    expected = Subscription(SomeEvent)

    assert SomeSubscriber.__subscription == expected


def test_subscribe_default_predicate():
    subscription = Subscription(SomeEvent)

    assert subscription.predicate(None)


def test_subscribe_with_predicate():
    def predicate(_):
        return False

    @subscribe(SomeEvent, predicate=predicate)
    class SomeSubscriber:
        pass

    expected = Subscription(SomeEvent, predicate)

    assert SomeSubscriber.__subscription == expected


def test_subscribe_invalid_subject():
    with pytest.raises(ValueError, match="subject must be a type"):

        @subscribe(None)
        class SomeSubscriber:
            pass


def test_subscribe_invalid_predicate():
    with pytest.raises(ValueError, match="predicate must be initialized"):

        @subscribe(SomeEvent, predicate=None)
        class SomeSubscriber:
            pass


def test_subscribe_once():
    @subscribe_once(SomeEvent)
    class SomeSubscriber:
        pass

    expected = Subscription(SomeEvent, once=True)

    assert SomeSubscriber.__subscription == expected
