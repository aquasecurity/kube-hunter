class ExternalServiceFailure(Exception):
    """
    This exception can be thrown when a service action has failed (e.g. unable to determine any IP address, no cache result available when offline)
    It is for user-code and external consumption of the service.
    """
    def __init__(self):
        pass

class ExternalProviderFailure(Exception):
    """
    This exception can be thrown when the provider of the service fails (e.g. the site is down, 400 error, etc.)
    It is for internal consumption of external services which will decide to act upon a provider failure, by providing a cached result or throw a service failure.
    """
    def __init__(self, exc=None):
        self.wrapped_exc = exc
