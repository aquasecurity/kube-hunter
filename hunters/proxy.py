from hunters.hunter import Hunter


class Proxy(Hunter):
    def __init__(self, host):
        self.host = host

    def hunt(self, *args, **kwargs):
        raise NotImplementedError()
