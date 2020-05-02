import functools
import logging
import queue

from collections import defaultdict
from threading import Thread
from typing import DefaultDict, Iterable, List, Type
from kube_hunter.core.pubsub.subscription import Event, EventFilter, Subscriber, Target

logger = logging.getLogger(__name__)


def class_name(cls: type):
    return f"{cls.__module__}.{cls.__qualname__}"


class EventRegistry:
    _records: DefaultDict[Type[Subscriber], List[Target]]

    def __init__(self):
        self._records = defaultdict(list)

    def add(self, subscriber: Type[Subscriber], target: Target):
        self._records[subscriber].append(target)

    def remove(self, subscriber: Type[Subscriber], target: Target):
        self._records[subscriber].remove(target)

    def get_subscribers(self, event: Event) -> Iterable[Type[Subscriber]]:
        subscribers = []
        for subscriber, targets in self._records.items():
            # MyPy errors when calling a function property: https://github.com/python/mypy/issues/5485
            if any(issubclass(t.subject, type(event)) and t.predicate(event) for t in targets):  # type: ignore
                subscribers.append(subscriber)
        return subscribers


class EventQueue:
    running: bool
    workers: List[Thread]
    queue: queue.Queue
    worker_poll_timeout: float
    hooks: EventRegistry
    filters: EventRegistry

    def __init__(self, workers=10):
        self.running = False
        self.queue = queue.Queue()
        self.workers = list()
        self.worker_poll_timeout = 1
        self.hooks = EventRegistry()
        self.filters = EventRegistry()
        self.workers = [Thread(target=self._worker, daemon=True) for _ in range(workers)]

    def start(self):
        self.running = True

        for worker in self.workers:
            worker.start()

    def register(self, subscriber: Type[Subscriber]):
        targets = getattr(subscriber, "subscription_targets", None)
        if not targets:
            raise ValueError("subscriber does not have subscriptions")

        for target in targets:
            self._add_subscription(subscriber, target)

    def unregister(self, subscriber: Type[Subscriber]):
        targets = subscriber.subscription_targets
        if not targets:
            raise ValueError("subscriber does not have subscriptions")

        try:
            for target in targets:
                self._remove_subscription(subscriber, target)
        except ValueError:
            raise ValueError("subscriber is not subscribed")

    def _event_registry(self, subscriber: Type[Subscriber]) -> EventRegistry:
        if issubclass(subscriber, EventFilter):
            return self.filters
        return self.hooks

    def _add_subscription(self, subscriber: Type[Subscriber], target: Target):
        @functools.wraps(subscriber.execute)
        def unregister(*args):
            self.unregister(subscriber)
            unregister.__wrapped__(*args)
            subscriber.execute = unregister.__wrapped__

        if target.once:
            # MyPy does not allow monkey patching: https://github.com/python/mypy/issues/2427
            subscriber.execute = unregister  # type: ignore

        logger.debug(f"Subscribing {class_name(subscriber)} to {target.subject}")
        self._event_registry(subscriber).add(subscriber, target)

    def _remove_subscription(self, subscriber: Type[Subscriber], target: Target):
        self._event_registry(subscriber).remove(subscriber, target)

    def _apply_filters(self, event):
        for filter_type in self.filters.get_subscribers(event):
            logger.debug(f"Event {class_name(event)} filtered with {class_name(filter_type)}")
            filter_instance = filter_type(event)
            filter_instance.execute()
            event = filter_instance.event

            # stop filter chain if a filter drops the event
            if not event:
                return None
        return event

    def _worker(self):
        while self.running:
            try:
                self._worker_iteration(self.queue.get(timeout=self.worker_poll_timeout))
                self.queue.task_done()
            except queue.Empty:
                logging.debug("waiting for queue")
        logger.debug("closing thread...")

    def _worker_iteration(self, subscriber):
        logger.debug(f"Executing {class_name(type(subscriber))} with {subscriber.event.__dict__}")
        try:
            for event in subscriber.execute():
                print("got event")
                self.publish_event(event, caller=subscriber)
        except Exception:
            logger.debug("unhandled exception in subscriber", exc_info=True)

    def publish_event(self, event, caller=None):
        logger.debug(f"Event {class_name(event)} got published with {event}")

        # link event to caller chain
        if caller:
            event.previous = caller.event
            event.hunter = caller.__class__

        # check for dropped event
        event = self._apply_filters(event)
        if not event:
            return

        # in case the event was rewritten, make sure it's linked to its previous event
        if caller:
            event.previous = caller.event
            event.hunter = caller.__class__

        for subscriber in self.hooks.get_subscribers(event):
            self.queue.put(subscriber(event))

    def finished(self):
        tasks_left = self.queue.unfinished_tasks
        if tasks_left:
            logger.debug(f"{tasks_left} tasks left")
        return not tasks_left

    def stop(self, wait=False):
        assert self.running, "not running"
        self.running = False
        if wait:
            self.queue.join()
