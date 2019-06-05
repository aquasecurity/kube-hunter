import logging
import time
from abc import ABCMeta
from collections import defaultdict
from queue import Queue
from threading import Lock, Thread

from __main__ import config

from ..types import ActiveHunter, Hunter, HunterBase

from ...core.events.types import HuntFinished, Vulnerability, EventFilterBase
import threading

global queue_lock
queue_lock = Lock()

# Inherits Queue object, handles events asynchronously
class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.passive_hunters = dict()
        self.active_hunters = dict()
        self.all_hunters = dict()

        self.hooks = defaultdict(list)
        self.filters = defaultdict(list)
        self.running = True
        self.workers = list()

        for i in range(num_worker):
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

    # getting uninstantiated event object
    def subscribe_event(self, event, hook=None, predicate=None):
        if ActiveHunter in hook.__mro__:
            if not config.active:
                return
            else:
                self.active_hunters[hook] = hook.__doc__
        elif HunterBase in hook.__mro__:
            self.passive_hunters[hook] = hook.__doc__

        if HunterBase in hook.__mro__:
            self.all_hunters[hook] = hook.__doc__

        # registering filters
        if EventFilterBase in hook.__mro__:
            if hook not in self.filters[event]:
                self.filters[event].append((hook, predicate))
                logging.debug('{} filter subscribed to {}'.format(hook, event))

        # registering hunters
        elif hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))
            logging.debug('{} subscribed to {}'.format(hook, event))

    # getting instantiated event object
    def publish_event(self, event, caller=None):
        # setting event chain
        if caller:
            event.previous = caller.event
            event.hunter = caller.__class__

        # applying filters to event
        for hooked_event in self.filters.keys():
            if hooked_event in event.__class__.__mro__:
                for filter_hook, predicate in self.filters[hooked_event]:
                    if predicate and not predicate(event):
                        continue

                    logging.debug('Event {} got filtered with {}'.format(event.__class__, filter_hook))
                    if not filter_hook(event).execute():
                        # filters the event, if returns None, does not proceed to publish it.
                        return

        # publishing to subscribers
        for hooked_event in self.hooks.keys():
            if hooked_event in event.__class__.__mro__:
                for hook, predicate in self.hooks[hooked_event]:
                    if predicate and not predicate(event):
                        continue

                    if config.statistics and caller:
                        if Vulnerability in event.__class__.__mro__:
                            caller.__class__.publishedVulnerabilities += 1

                    logging.debug('Event {} got published with {}'.format(event.__class__, event))
                    self.put(hook(event))

    # executes callbacks on dedicated thread as a daemon
    def worker(self):
        while self.running:
            queue_lock.acquire()
            hook = self.get()
            queue_lock.release()
            try:
                hook.execute()
            except Exception as ex:
                logging.debug(ex)
            self.task_done()
        logging.debug("closing thread...")

    def notifier(self):
        time.sleep(2)
        while self.unfinished_tasks > 0:
            logging.debug("{} tasks left".format(self.unfinished_tasks))
            time.sleep(3)

    # stops execution of all daemons
    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()

handler = EventQueue(800)
