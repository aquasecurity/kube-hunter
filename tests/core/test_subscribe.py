import time

from kube_hunter.conf import Config, set_config
from kube_hunter.core.types import Hunter
from kube_hunter.core.events.types import Event, Service
from kube_hunter.core.events import handler

counter = 0
first_run = True

set_config(Config())


class OnceOnlyEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Once Service")


class RegularEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Service")


class AnotherRegularEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Service (another)")


class DifferentRegularEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Service (different)")


@handler.subscribe_once(OnceOnlyEvent)
class OnceHunter(Hunter):
    def __init__(self, event):
        global counter
        counter += 1


@handler.subscribe(RegularEvent)
class RegularHunter(Hunter):
    def __init__(self, event):
        global counter
        counter += 1


@handler.subscribe_many([DifferentRegularEvent, AnotherRegularEvent])
class SmartHunter(Hunter):
    def __init__(self, events):
        global counter, first_run
        counter += 1

        # we add an attribute on the second scan.
        # here we test that we get the latest event
        different_event = events.get_by_class(DifferentRegularEvent)
        if first_run:
            first_run = False
            assert not different_event.new_value
        else:
            assert different_event.new_value


@handler.subscribe_many([DifferentRegularEvent, AnotherRegularEvent])
class SmartHunter2(Hunter):
    def __init__(self, events):
        global counter
        counter += 1

        # check if we can access the events
        assert events.get_by_class(DifferentRegularEvent).__class__ == DifferentRegularEvent
        assert events.get_by_class(AnotherRegularEvent).__class__ == AnotherRegularEvent


def test_subscribe_mechanism():
    global counter
    counter = 0

    # first test normal subscribe and publish works
    handler.publish_event(RegularEvent())
    handler.publish_event(RegularEvent())
    handler.publish_event(RegularEvent())

    time.sleep(0.02)
    assert counter == 3


def test_subscribe_once_mechanism():
    global counter
    counter = 0

    # testing the multiple subscription mechanism
    handler.publish_event(OnceOnlyEvent())

    time.sleep(0.02)
    assert counter == 1
    counter = 0

    handler.publish_event(OnceOnlyEvent())
    handler.publish_event(OnceOnlyEvent())
    handler.publish_event(OnceOnlyEvent())
    time.sleep(0.02)

    assert counter == 0


def test_subscribe_many_mechanism():
    global counter
    counter = 0

    # testing the multiple subscription mechanism
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(AnotherRegularEvent())

    time.sleep(0.02)
    # We expect SmartHunter and SmartHunter2 to be executed once. hence the counter should be 2
    assert counter == 2
    counter = 0

    # Test using most recent event
    newer_version_event = DifferentRegularEvent()
    newer_version_event.new_value = True
    handler.publish_event(newer_version_event)

    assert counter == 2
