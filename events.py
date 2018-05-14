import logging
from Queue import Queue
from threading import Thread
from collections import defaultdict
from threading import Lock
from abc import ABCMeta

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
                self.put(hook(event))

    # executes callbacks on dedicated thread
    def worker(self):
        while self.running:
            hook = self.get()
            hook.execute()
            self.task_done()

    def free(self):
        self.running = False
        with self.mutex:
            self.queue.clear()


handler = EventQueue(500)

print_lock = Lock()
def safe_print(*args, **kargs):
    with print_lock:
        print(args, kargs)

    

""" Parent Event Objects """
class NetworkEvent(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port

class ServiceEvent(NetworkEvent):
    def __init__(self, secure, location, host, port):
        super(ServiceEvent, self).__init__(host=host, port=port)
        self.secure = secure
        self.location = location       

""" Event Objects """
class NewHostEvent(NetworkEvent):
    def __init__(self, host, port=0):
        super(NewHostEvent, self).__init__(port=port, host=host)
    
    def __str__(self):
        return str(self.host)

class OpenPortEvent(NetworkEvent):
    def __init__(self, host, port):
        super(OpenPortEvent, self).__init__(port=port, host=host)

    def __str__(self):
        return str(self.port)

class KubeProxyEvent(ServiceEvent):
    def __init__(self, host, port=8001, secure=True, location=""):
        super(KubeProxyEvent, self).__init__(secure=secure, location=location, host=host, port=port)

class KubeDashboardEvent(ServiceEvent):
    def __init__(self, host, secure=True, port=30000, location=""):
        super(KubeDashboardEvent, self).__init__(location=location, secure=secure, host=host, port=port)
        