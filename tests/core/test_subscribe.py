import time

from kube_hunter.core.types import Hunter
from kube_hunter.core.events.types import Event, Service
from kube_hunter.core.events import handler

counter = 0

class OnceOnlyEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Once Service")

class RegularEvent(Service, Event):
    def __init__(self):
        Service.__init__(self, "Test Service")

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


def test_subscribe_mechanism():
    global counter

    # first test normal subscribe and publish works
    handler.publish_event(RegularEvent())
    handler.publish_event(RegularEvent())
    handler.publish_event(RegularEvent())

    time.sleep(0.02)
    assert counter == 3
    counter = 0

    # testing the subscribe_once mechanism
    handler.publish_event(OnceOnlyEvent())
    handler.publish_event(OnceOnlyEvent())
    handler.publish_event(OnceOnlyEvent())

    time.sleep(0.02)
    # should have been triggered once
    assert counter == 1
