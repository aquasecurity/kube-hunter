from ..events import handler

class Hunter(object):
    def __init__(self):
        pass

    def publish_event(self, event):
        handler.publish_event(event, caller=self)
