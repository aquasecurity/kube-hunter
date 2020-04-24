import functools

from dataclasses import dataclass
from typing import Callable
from kube_hunter.core.events.types import Event


def _default_predicate(_):
    return True


@dataclass
class Subscription:
    subject: type
    predicate: Callable[[Event], bool] = _default_predicate
    once: bool = False


def subscribe(subject, predicate=_default_predicate, once=False):
    def wrapper(cls):
        cls.__subscription = Subscription(subject, predicate, once)
        return cls

    if not isinstance(subject, type):
        raise ValueError("subject must be a type")
    if not predicate:
        raise ValueError("predicate must be initialized")

    return wrapper


subscribe_once = functools.partial(subscribe, once=True)
