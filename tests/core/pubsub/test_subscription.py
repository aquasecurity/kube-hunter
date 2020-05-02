import pytest

from kube_hunter.core.pubsub.subscription import Event, Subscriber, Target, subscribe, subscribe_once


class SomeEvent(Event):
    pass


def test_subscribe_default_values():
    @subscribe(SomeEvent)
    class SomeSubscriber(Subscriber):
        pass

    expected = [Target(SomeEvent)]

    assert SomeSubscriber.subscription_targets == expected


def test_subscribe_default_predicate():
    @subscribe(SomeEvent)
    class SomeSubscriber(Subscriber):
        pass

    assert SomeSubscriber.subscription_targets[0].predicate(None)


def test_subscribe_with_predicate():
    def predicate(_):
        return False

    @subscribe(SomeEvent, predicate=predicate)
    class SomeSubscriber(Subscriber):
        pass

    expected = [Target(SomeEvent, predicate)]

    assert SomeSubscriber.subscription_targets == expected


def test_subscribe_invalid_subject():
    with pytest.raises(ValueError, match="subject must be a type"):

        @subscribe(None)
        class SomeSubscriber(Subscriber):
            pass


def test_subscribe_invalid_predicate():
    with pytest.raises(ValueError, match="predicate must be initialized"):

        @subscribe(SomeEvent, predicate=None)
        class SomeSubscriber(Subscriber):
            pass


def test_subscribe_once():
    @subscribe_once(SomeEvent)
    class SomeSubscriber(Subscriber):
        pass

    expected = [Target(SomeEvent, once=True)]

    assert SomeSubscriber.subscription_targets == expected
