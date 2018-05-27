from defaults import Event

class Vulnerability(object):
    """ Information Events """
    # this kind of events will be triggered when important information is discovered
    def __init__(self, desc):
        self.desc = desc

class KubeletVulnerability(Vulnerability, Event):
    def __init__(self, **kargs):
        super(KubeletVulnerability, self).__init__(**kargs)