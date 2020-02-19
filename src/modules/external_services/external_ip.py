from collections import namedtuple

import requests

from .exceptions import ExternalProviderFailure, ExternalServiceFailure


def generic_text_http_provider(url):
    try:
        return requests.get(url).text
    except requests.ConnectionError as e:
        raise ExternalProviderFailure(e)

ExternalIPProvider = namedtuple('ExternalIPProvider', [
    'provide', # provide the current address IP.
    'priority' # it means: secure, no logs, etc.
])

CanHazIP = ExternalIPProvider(provide=generic_text_http_provider('https://canhazip.com'), priority=0)
Ipify = ExternalIPProvider(provide=generic_text_http_provider('https://api.ipify.org'), priority=1)

DEFAULT_PROVIDERS = [CanHazIP, Ipify]

class ExternalIPService:
    def __init__(self, providers=None, cache_results=True):
        if providers and not all(isinstance(i, ExternalIPProvider) for i in providers):
            raise TypeError('A provider must be of type `ExternalIPProvider`!')

        # Order provider by priority
        self.providers = sorted(providers or DEFAULT_PROVIDERS, key=lambda provider: provider.priority, reverse=True)
        self.cache_results = cache_results
        self.cached_ip = None

    def try_get(self, use_cache=True):
        if use_cache and self.cache_results and self.cached_ip:
            return self.cached_ip

        last_exc = None
        for provider in self.providers:
            try:
                ip = provider.provide()

                if self.cache_results:
                    self.cached_ip = ip

                return ip
            except ExternalProviderFailure as exc:
                last_exc = exc

        # Tough luck.
        raise ExternalServiceFailure(exc=last_exc)
