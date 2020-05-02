import abc
import functools

from dataclasses import dataclass
from typing import Callable, ClassVar, Iterable, List, Optional, Type


class Event:
    def __init__(self):
        self.previous = None
        self.hunter = None

    # newest attribute gets selected first
    def __getattr__(self, name):
        if name != "previous":
            for event in self.history:
                if name in event.__dict__:
                    return event.__dict__[name]
        return None

    # Event's logical location to be used mainly for reports.
    # If event don't implement it check previous event
    # This is because events are composed (previous -> previous ...)
    # and not inherited
    def location(self):
        location = None
        if self.previous:
            location = self.previous.location()

        return location

    # returns the event history ordered from newest to oldest
    @property
    def history(self):
        previous, history = self.previous, list()
        while previous:
            history.append(previous)
            previous = previous.previous
        return history


def _default_predicate(_):
    return True


@dataclass
class Target:
    subject: Type[Event]
    predicate: Callable[[Event], bool] = _default_predicate
    once: bool = False


class Subscriber(metaclass=abc.ABCMeta):
    subscription_targets: ClassVar[Optional[List[Target]]] = None
    event: Event

    def __init__(self, event: Event):
        self.event = event

    @abc.abstractmethod
    def execute(self) -> Iterable[Event]:
        pass


class EventFilter(Subscriber):
    @abc.abstractmethod
    def execute(self) -> Event:  # type: ignore # TODO: make differente interface for event publishers and filters
        pass


def subscribe(subject, predicate=_default_predicate, once=False):
    def wrapper(cls: Type[Subscriber]):
        if not isinstance(cls.subscription_targets, list):
            cls.subscription_targets = []
        cls.subscription_targets.append(Target(subject, predicate, once))
        return cls

    if not isinstance(subject, type):
        raise ValueError("subject must be a type")
    if not predicate:
        raise ValueError("predicate must be initialized")

    return wrapper


subscribe_once = functools.partial(subscribe, once=True)
