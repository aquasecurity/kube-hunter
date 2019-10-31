from .exceptions import ExternalServiceFailure, ExternalProviderFailure

import requests
from collections import namedtuple

def generic_text_http_provider(url):
    try:
        return requests.get(url).text
    except requests.ConnectionError as e:
        raise ExternalProviderFailure(e)

ExtIPProvider = namedtuple('ExternalIPProvider', [
    'handler',
    'priority' # it means: secure, no logs, etc.
])

CanHazIP = ExtIPProvider(handler=generic_text_http_provider('https://canhazip.com'), priority=0)
Ipify = ExtIPProvider(handler=generic_text_http_provider('https://api.ipify.org'), priority=1)

DEFAULT_PROVIDERS = [CanHazIP, Ipify]

class ExternalIPService:
    def __init__(self, providers=None, cache_results=True):
        if providers and not all(isinstance(i, ExtIPProvider) for i in providers):
            raise TypeError('A provider must be of type `ExternalIPProvider`!')
        
        # Order provider by priority
        self.providers = sorted(providers or DEFAULT_PROVIDERS, key=lambda provider: provider.priority, reverse=True)
        self.cache_results = cache_results

    def try_get(self, bypass_cache=False):
        if not bypass_cache and self.cache_results and self.cached_ip:
            return self.cached_ip
        
        last_exc = None
        for provider in self.providers:
            try:
                ip = provider.handler()
                self.cached_ip = ip
                return ip
            except ExternalProviderFailure as exc:
                last_exc = exc
        
        # Tough luck.
        raise ExternalServiceFailure(exc=last_exc)
