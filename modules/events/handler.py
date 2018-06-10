import inspect
import logging
from abc import ABCMeta
from collections import defaultdict
from Queue import Queue
from threading import Lock, Thread

working_count = 0
lock = Lock()

# Inherits Queue object, handles events asynchronously
class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.hooks = defaultdict(list)
        self.running = True

        for i in range(num_worker):
            t = Thread(target=self.worker)
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
        logging.debug('{} subscribed to {}'.format(hook, event))
        if hook not in self.hooks[event]:
            self.hooks[event].append((hook, predicate))

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
            hook.execute()
            self.task_done()
        logging.debug("closing thread...")

    # stops execution of all daemons
    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()


handler = EventQueue(800)
