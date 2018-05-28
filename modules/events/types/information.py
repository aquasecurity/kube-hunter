from common import Event

class Vulnerability(object):
    """ Information Events """
    # this kind of events will be triggered when important information is discovered
    def __init__(self, desc):
        self.desc = desc

class KubeletDebugHandler(Vulnerability, Event):
    def __init__(self, **kargs):
        super(KubeletDebugHandler, self).__init__(**kargs)