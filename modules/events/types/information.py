from common import Event

class Vulnerability(object):
    """ Information Events """
    # this kind of events will be triggered when important information is discovered
    def __init__(self, name, data=""):
        self.name = name
        self.data = data

    def explain(self):
        return self.data
