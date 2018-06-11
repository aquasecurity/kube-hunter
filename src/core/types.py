class ActiveHunter(object):    
    def publish_event(self, event):
        handler.publish_event(event, caller=self)


class Hunter(object):
    def publish_event(self, event):
        handler.publish_event(event, caller=self)

from events import handler # import is in the bottom to break import loops