from Queue import Queue
from threading import Thread
from collections import defaultdict
from threading import Lock


# Inherits Queue object, handles events asynchronously
class EventQueue(Queue, object):
    def __init__(self, num_worker=10):
        super(EventQueue, self).__init__()
        self.hooks = defaultdict(list)

        for i in range(num_worker):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()

    def publish_event(self, name, item):
        if name in self.hooks:
            safe_print('Event {} got published with {}'.format(name, item))
            for single_hook in self.hooks[name]:
                self.put(single_hook(item))

    def subscribe_event(self, name, callback):
        safe_print('Subscribed: {} to {} '.format(name, callback))
        if callback not in self.hooks[name]:
            self.hooks[name].append(callback)
    
    # executes callbacks on dedicated thread
    def worker(self):
        while True:
            hook = self.get()
            hook.execute()
            self.task_done()



print_lock = Lock()
def safe_print(*args, **kargs):
    with print_lock:
        print(args, kargs)
    

handler = EventQueue(500)
       