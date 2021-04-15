import logging
import time
from collections import defaultdict
from queue import Queue
from threading import Thread

from kube_hunter.conf import get_config
from kube_hunter.core.types import ActiveHunter, HunterBase
from kube_hunter.core.events.types import Vulnerability, EventFilterBase

logger = logging.getLogger(__name__)


# Inherits Queue object, handles events asynchronously
class EventQueue(Queue):
    def __init__(self, num_worker=10):
        super().__init__()
        self.passive_hunters = dict()
        self.active_hunters = dict()
        self.all_hunters = dict()

        self.hooks = defaultdict(list)
        self.filters = defaultdict(list)
        self.multi_hooks = defaultdict(list) # for hooks which listens for multiple events.
        self.hook_dependencies = defaultdict(set) # dependencies which were defined for a given hook.
        self.hook_fulfilled_deps = defaultdict(set) # keep track of already fulfilled dependencies.
        self.running = True
        self.workers = list()

        for _ in range(num_worker):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.workers.append(t)

        t = Thread(target=self.notifier)
        t.daemon = True
        t.start()

    # decorator wrapping for easy subscription
    def subscribe(self, event, hook=None, predicate=None):
        def wrapper(hook):
            self.subscribe_event(event, hook=hook, predicate=predicate)
            return hook

        return wrapper

    # decorator wrapping for multiple subscriptions
    def subscribe_many(self, events, predicates=None):
        def wrapper(hook):
            self.subscribe_events(events, hook=hook, predicates=predicates)
            return hook

        return wrapper

    # wrapper takes care of the subscribe once mechanism
    def subscribe_once(self, event, hook=None, predicate=None):
        def wrapper(hook):
            # installing a __new__ magic method on the hunter
            # which will remove the hunter from the list upon creation
            def __new__unsubscribe_self(self, cls):
                handler.hooks[event].remove((hook, predicate))
                return object.__new__(self)

            hook.__new__ = __new__unsubscribe_self

            self.subscribe_event(event, hook=hook, predicate=predicate)
            return hook

        return wrapper

    # register hunter in tables, return True if the hunter should be used otherwise False (active mode vs passive mode)
    def _register_hunters(self, hook=None):
        if ActiveHunter in hook.__mro__:
            if not config.active:
                return False
            else:
                self.active_hunters[hook] = hook.__doc__
        elif HunterBase in hook.__mro__:
            self.passive_hunters[hook] = hook.__doc__

        if HunterBase in hook.__mro__:
            self.all_hunters[hook] = hook.__doc__

        return True

    def _register_filter(self, event, hook=None, predicate=None):
        if hook not in self.filters[event]:
            self.filters[event].append((hook, predicate))
            logging.debug('{} filter subscribed to {}'.format(hook, event))

    def _register_hook(self, event, hook=None, predicate=None):
        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))
            logging.debug('{} subscribed to {}'.format(hook, event))

    def subscribe_event(self, event, hook=None, predicate=None):
        if not self._register_hunters(hook):
            return

        # registering filters
        if EventFilterBase in hook.__mro__:
            self._register_filter(event, hook, predicate)
        # registering hunters
        else:
            self._register_hook(event, hook, predicate)

    def subscribe_events(self, events, hook=None, predicates=None):
        if not self._register_hunters(hook):
            return False

        if predicates is None:
            predicates = [None] * len(events)

        # registering filters.
        if EventFilterBase in hook.__mro__:
            for event, predicate in zip(events, predicates):
                self._register_filter(event, hook, predicate)
        # registering hunters.
        else:
            for event, predicate in zip(events, predicates):
                self.multi_hooks[event].append((hook, predicate))

            self.hook_dependencies[hook] = frozenset(events)

    def apply_filters(self, event):
        # if filters are subscribed, apply them on the event
        for hooked_event in self.filters.keys():
            if hooked_event in event.__class__.__mro__:
                for filter_hook, predicate in self.filters[hooked_event]:
                    if predicate and not predicate(event):
                        continue

                    logger.debug(f"Event {event.__class__} filtered with {filter_hook}")
                    event = filter_hook(event).execute()
                    # if filter decided to remove event, returning None
                    if not event:
                        return None
        return event

    def _set_event_chain(self, event, caller):
        if caller:
            event.previous = caller.event
            event.hunter = caller.__class__

    def _increase_vuln_count(self, event, caller):
        if config.statistics and caller:
            if Vulnerability in event.__class__.__mro__:
                caller.__class__.publishedVulnerabilities += 1

    def mark_and_fire_if_possible(self, hooked_event, hook):
        # Sanity check.
        assert (hooked_event in self.hook_dependencies[hook])

        self.hook_fulfilled_deps[hook].add(hooked_event)

        if len(self.hook_fulfilled_deps[hook]) == len(self.hook_dependencies[hook]):
            # fire it!
            self.put(hook(self.hook_fulfilled_deps[hook]))
            # reset the state.
            self.hook_fulfilled_deps[hook] = set()

    # getting instantiated event object
    def publish_event(self, event, caller=None):
        # setting event chain
        self._set_event_chain(event, caller)

        # applying filters on the event, before publishing it to subscribers.
        # if filter returned None, not proceeding to publish
        event = self.apply_filters(event)
        if event:
            # If event was rewritten, make sure it's linked to its parent ('previous') event
            self._set_event_chain(event, caller)

            for hooked_event in self.hooks.keys():
                if hooked_event in event.__class__.__mro__:
                    for hook, predicate in self.hooks[hooked_event]:
                        if predicate and not predicate(event):
                            continue

                        self._increase_vuln_count(event, caller)

                        logger.debug(f"Event {event.__class__} got published with {event}")
                        self.put(hook(event))

                    for hook, predicate in self.multi_hooks[hooked_event]:
                        if predicate and not predicate(event):
                            continue

                        logging.debug('Event {} got published with {}'.format(event.__class__, event))
                        self._increase_vuln_count(event, caller)
                        self.mark_and_fire_if_possible(hooked_event, hook)


    # executes callbacks on dedicated thread as a daemon
    def worker(self):
        while self.running:
            try:
                hook = self.get()
                logger.debug(f"Executing {hook.__class__} with {hook.event.__dict__}")
                hook.execute()
            except Exception as ex:
                logger.debug(ex, exc_info=True)
            finally:
                self.task_done()
        logger.debug("closing thread...")

    def notifier(self):
        time.sleep(2)
        # should consider locking on unfinished_tasks
        while self.unfinished_tasks > 0:
            logger.debug(f"{self.unfinished_tasks} tasks left")
            time.sleep(3)
            if self.unfinished_tasks == 1:
                logger.debug("final hook is hanging")

    # stops execution of all daemons
    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()


handler = EventQueue(800)
