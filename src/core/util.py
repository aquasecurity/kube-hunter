import os

from __main__ import config


def get_client_cert():
    if config.clientcert and config.clientkey:
        return config.clientcert, config.clientkey
    elif config.clientcert:
        return config.clientcert
    else:
        return None
