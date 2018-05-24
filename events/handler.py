import inspect
import logging
from abc import ABCMeta
from collections import defaultdict
from Queue import Queue
from threading import Lock, Thread

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
        logging.debug('{} subscribed to {}'.format(event.__name__, hook))
        if hook not in self.hooks[event.__name__]:
            self.hooks[event.__name__].append((hook, predicate))

    # getting instantiated event object
    def publish_event(self, event):
        logging.debug('Event {} got published with {}'.format(event.__class__.__name__, event))
        event_name = event.__class__.__name__
        if event_name in self.hooks:
            for hook, predicate in self.hooks[event_name]:
                if predicate and not predicate(event):
                    continue

                # access to stack frame, can also be implemented by changing the function call to recieve self.
                # TODO: decide whether invisibility to the developer is the best approach
                last_frame = inspect.stack()[1][0]
                if "self" in last_frame.f_locals:
                    event.previous = last_frame.f_locals["self"].event
                
                self.put(hook(event))

    # executes callbacks on dedicated thread as a daemon
    def worker(self):
        while self.running:
            hook = self.get()
            hook.execute()
            self.task_done()

    # stops execution of all daemons
    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()


handler = EventQueue(800)

