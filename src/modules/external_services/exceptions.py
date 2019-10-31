class ExternalServiceFailure(Exception):
    def __init__(self):
        pass

class ExternalProviderFailure(Exception):
    def __init__(self, exc=None):
        self.wrapped_exc = exc
