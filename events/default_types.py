# class EventMeta(type):
#     def __init__(cls, name, bases, dct):
#         super(EventMeta, cls).__init__(name, bases, dct)

""" Parent Event Objects """
class NetworkEvent(object):
    # __metaclass__ = EventMeta
    def __init__(self, host, port):
        self.host = host
        self.port = port

class ServiceEvent(NetworkEvent):
    # __metaclass__ = EventMeta
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
        