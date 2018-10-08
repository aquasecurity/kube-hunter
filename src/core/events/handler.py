import logging
import time
from abc import ABCMeta
from collections import defaultdict
from Queue import Queue
from threading import Lock, Thread

from __main__ import config

from ..types import ActiveHunter, Hunter

from ...core.events.types import HuntFinished

working_count = 0
lock = Lock()

# Inherits Queue object, handles events asynchronously
class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.passive_hunters = dict()
        self.active_hunters = dict()

        self.hooks = defaultdict(list)
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
        elif Hunter in hook.__mro__:
            self.passive_hunters[hook] = hook.__doc__

        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))
            logging.debug('{} subscribed to {}'.format(hook, event))

    # getting instantiated event object
    def publish_event(self, event, caller=None):
        logging.debug('Event {} got published with {}'.format(event.__class__, event))
        for hooked_event in self.hooks.keys():
            if hooked_event in event.__class__.__mro__:
                for hook, predicate in self.hooks[hooked_event]:
                    if predicate and not predicate(event):
                        continue

                    if caller:
                        event.previous = caller.event
                    self.put(hook(event))

    # executes callbacks on dedicated thread as a daemon
    def worker(self):
        while self.running:
            hook = self.get()
            try:
                hook.execute()
            except Exception as ex:
                logging.debug(ex.message)
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
