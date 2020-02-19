import time

from src.core.types import Hunter
from src.core.events.types import Event, Service
from src.core.events import handler

counter = 0

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
        global counter
        counter += 1

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
    handler.publish_event(AnotherRegularEvent())
    handler.publish_event(DifferentRegularEvent())

    time.sleep(0.02)
    # We expect that SmartHunter to run once and RegularEvent to run once.
    assert counter == 2
    counter = 0

    handler.publish_event(AnotherRegularEvent())
    handler.publish_event(AnotherRegularEvent())
    handler.publish_event(AnotherRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())
    handler.publish_event(DifferentRegularEvent())

    time.sleep(0.02)
    # (Regular, Another) or (Another, Regular) sequences trigger the SmartHunter.
    # Regular trigger the RegularHunter.
    # OnceHunter should not be triggered here.
    assert counter == 1

