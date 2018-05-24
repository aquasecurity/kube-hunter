import logging 

from events import handler, ReadOnlyKubeletEvent, SecureKubeletEvent

""" dividing ports for seperate hunters """
@handler.subscribe(ReadOnlyKubeletEvent)
class ReadOnlyKubeletPortHunter(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("[OPEN SERVICE] INSECURED KUBELET API - {}:{}".format(self.event.host, self.event.port))
        
@handler.subscribe(SecureKubeletEvent)        
class SecurePortKubeletHunter(object):
    def __init__(self, event):
        self.event = event

    def execute(self):
        logging.info("[OPEN SERVICE] SECURED KUBELET API - {}:{}".format(self.event.host, self.event.port))