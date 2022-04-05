import logging
import time
from collections import defaultdict
from queue import Queue
from threading import Thread

from kube_hunter.conf import get_config
from kube_hunter.core.types import ActiveHunter, HunterBase
from kube_hunter.core.events.types import Vulnerability, EventFilterBase, MultipleEventsContainer

logger = logging.getLogger(__name__)


# Inherits Queue object, handles events asynchronously
class EventQueue(Queue):
    def __init__(self, num_worker=10):
        super().__init__()
        self.passive_hunters = dict()
        self.active_hunters = dict()
        self.all_hunters = dict()

        self.running = True
        self.workers = list()

        # -- Regular Subscription --
        # Structure: key: Event Class, value: tuple(Registered Hunter, Predicate Function)
        self.hooks = defaultdict(list)
        self.filters = defaultdict(list)
        # --------------------------

        # -- Multiple Subscription --
        # Structure: key: Event Class, value: tuple(Registered Hunter, Predicate Function)
        self.multi_hooks = defaultdict(list)

        # When subscribing to multiple events, this gets populated with required event classes
        # Structure: key: Hunter Class, value: set(RequiredEventClass1, RequiredEventClass2)
        self.hook_dependencies = defaultdict(set)

        # To keep track of fulfilled dependencies. we need to have a structure which saves historical instanciated
        # events mapped to a registered hunter.
        # We used a 2 dimensional dictionary in order to fulfill two demands:
        #   * correctly count published required events
        #   * save historical events fired, easily sorted by their type
        #
        # Structure: hook_fulfilled_deps[hunter_class] -> fulfilled_events_for_hunter[event_class] -> [EventObject, EventObject2]
        self.hook_fulfilled_deps = defaultdict(lambda: defaultdict(list))
        # ---------------------------

        for _ in range(num_worker):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            self.workers.append(t)

        t = Thread(target=self.notifier)
        t.daemon = True
        t.start()

    """
    ######################################################
    + ----------------- Public Methods ----------------- +
    ######################################################
    """

    def subscribe(self, event, hook=None, predicate=None, is_register=True):
        """
        The Subscribe Decorator - For Regular Registration
        Use this to register for one event only. Your hunter will execute each time this event is published

        @param event - Event class to subscribe to
        @param predicate - Optional: Function that will be called with the published event as a parameter before trigger.
                            If it's return value is False, the Hunter will not run (default=None).
        @param hook - Hunter class to register for (ignore when using as a decorator)
        """

        def wrapper(hook):
            self.subscribe_event(event, hook=hook, predicate=predicate, is_register=is_register)
            return hook

        return wrapper

    def subscribe_many(self, events, hook=None, predicates=None, is_register=True):
        """
        The Subscribe Many Decorator - For Multiple Registration,
        When your attack needs several prerequisites to exist in the cluster, You need to register for multiple events.
        Your hunter will execute once for every new combination of required events.
        For example:
            1. event A was published 3 times
            2. event B was published once.
            3. event B was published again
        Your hunter will execute 2 times:
            * (on step 2) with the newest version of A
            * (on step 3) with the newest version of A and newest version of B

        @param events - List of event classes to subscribe to
        @param predicates - Optional: List of function that will be called with the published event as a parameter before trigger.
                            If it's return value is False, the Hunter will not run (default=None).
        @param hook - Hunter class to register for (ignore when using as a decorator)
        """

        def wrapper(hook):
            self.subscribe_events(events, hook=hook, predicates=predicates, is_register=is_register)
            return hook

        return wrapper

    def subscribe_once(self, event, hook=None, predicate=None, is_register=True):
        """
        The Subscribe Once Decorator - For Single Trigger Registration,
        Use this when you want your hunter to execute only in your entire program run
        wraps subscribe_event method

        @param events - List of event classes to subscribe to
        @param predicates - Optional: List of function that will be called with the published event as a parameter before trigger.
                            If it's return value is False, the Hunter will not run (default=None).
        @param hook - Hunter class to register for (ignore when using as a decorator)
        """

        def wrapper(hook):
            # installing a __new__ magic method on the hunter
            # which will remove the hunter from the list upon creation
            def __new__unsubscribe_self(self, cls):
                handler.hooks[event].remove((hook, predicate))
                return object.__new__(self)

            hook.__new__ = __new__unsubscribe_self

            self.subscribe_event(event, hook=hook, predicate=predicate, is_register=is_register)

            return hook

        return wrapper

    def publish_event(self, event, caller=None):
        """
        The Publish Event Method - For Publishing Events To Kube-Hunter's Queue
        """
        # Document that the hunter published a vulnerability (if it's indeed a vulnerability)
        # For statistics options
        self._increase_vuln_count(event, caller)

        # sets the event's parent to be it's publisher hunter.
        self._set_event_chain(event, caller)

        # applying filters on the event, before publishing it to subscribers.
        # if filter returned None, not proceeding to publish
        event = self.apply_filters(event)
        if event:
            # If event was rewritten, make sure it's linked again
            self._set_event_chain(event, caller)

            # Regular Hunter registrations - publish logic
            # Here we iterate over all the registered-to events:
            for hooked_event in self.hooks.keys():
                # We check if the event we want to publish is an inherited class of the current registered-to iterated event
                # Meaning - if this is a relevant event:
                if hooked_event in event.__class__.__mro__:
                    # If so, we want to publish to all registerd hunters.
                    for hook, predicate in self.hooks[hooked_event]:
                        if predicate and not predicate(event):
                            continue

                        self.put(hook(event))
                        logger.debug(f"Event {event.__class__} got published to hunter - {hook} with {event}")

            # Multiple Hunter registrations - publish logic
            # Here we iterate over all the registered-to events:
            for hooked_event in self.multi_hooks.keys():
                # We check if the event we want to publish is an inherited class of the current registered-to iterated event
                # Meaning - if this is a relevant event:
                if hooked_event in event.__class__.__mro__:
                    # now we iterate over the corresponding registered hunters.
                    for hook, predicate in self.multi_hooks[hooked_event]:
                        if predicate and not predicate(event):
                            continue

                        self._update_multi_hooks(hook, event)

                        if self._is_all_fulfilled_for_hunter(hook):
                            events_container = MultipleEventsContainer(self._get_latest_events_from_multi_hooks(hook))
                            self.put(hook(events_container))
                            logger.debug(
                                f"Multiple subscription requirements were met for hunter {hook}. events container was \
                                published with {self.hook_fulfilled_deps[hook].keys()}"
                            )

    """
    ######################################################
    + ---------------- Private Methods ----------------- +
    + ---------------- (Backend Logic) ----------------- +
    ######################################################
    """

    def _get_latest_events_from_multi_hooks(self, hook):
        """
        Iterates over fulfilled deps for the hunter, and fetching the latest appended events from history
        """
        latest_events = list()
        for event_class in self.hook_fulfilled_deps[hook].keys():
            latest_events.append(self.hook_fulfilled_deps[hook][event_class][-1])
        return latest_events

    def _update_multi_hooks(self, hook, event):
        """
        Updates published events in the multi hooks fulfilled store.
        """
        self.hook_fulfilled_deps[hook][event.__class__].append(event)

    def _is_all_fulfilled_for_hunter(self, hook):
        """
        Returns true for multi hook fulfilled, else oterwise
        """
        # Check if the first dimension already contains all necessary event classes
        return len(self.hook_fulfilled_deps[hook].keys()) == len(self.hook_dependencies[hook])

    def _set_event_chain(self, event, caller):
        """
        Sets' events attribute chain.
        In here we link the event with it's publisher (Hunter),
        so in the next hunter that catches this event, we could access the previous one's attributes.

        @param event: the event object to be chained
        @param caller: the Hunter object that published this event.
        """
        if caller:
            event.previous = caller.event
            event.hunter = caller.__class__

    def _register_hunters(self, hook=None):
        """
        This method is called when a Hunter registers itself to the handler.
        this is done in order to track and correctly configure the current run of the program.

        passive_hunters, active_hunters, all_hunters
        """
        config = get_config()
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
            logging.debug("{} filter subscribed to {}".format(hook, event))

    def _register_hook(self, event, hook=None, predicate=None):
        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))
            logging.debug("{} subscribed to {}".format(hook, event))

    def allowed_for_custom_registration(self, target_hunter):
        """
        Check if the partial input list contains the hunter we are about to register for events
        If hunter is considered a Core hunter as specified in `config.core_hunters` we allow it anyway

        Returns true if:
         1. partial hunt is disabled
         2. partial hunt is enabled and hunter is in core hunter class
         3. partial hunt is enabled and hunter is specified in config.partial

        @param target_hunter: hunter class for registration check
        """
        config = get_config()
        if not config.custom:
            return True

        hunter_class_name = target_hunter.__name__
        if hunter_class_name in config.core_hunters or hunter_class_name in config.custom:
            return True

        return False

    def subscribe_event(self, event, hook=None, predicate=None, is_register=True):
        if not is_register:
            return
        if not self.allowed_for_custom_registration(hook):
            return
        if not self._register_hunters(hook):
            return

        # registering filters
        if EventFilterBase in hook.__mro__:
            self._register_filter(event, hook, predicate)
        # registering hunters
        else:
            self._register_hook(event, hook, predicate)

    def subscribe_events(self, events, hook=None, predicates=None, is_register=True):
        if not is_register:
            return
        if not self.allowed_for_custom_registration(hook):
            return
        if not self._register_hunters(hook):
            return

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

    def _increase_vuln_count(self, event, caller):
        config = get_config()
        if config.statistics and caller:
            if Vulnerability in event.__class__.__mro__:
                caller.__class__.publishedVulnerabilities += 1

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


config = get_config()
handler = EventQueue(config.num_worker_threads)
