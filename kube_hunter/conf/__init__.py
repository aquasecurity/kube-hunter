import logging
from kube_hunter.conf.parser import arg_parse

config = arg_parse()

loglevel = getattr(logging, config.log.upper(), logging.INFO)

if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(message)s', datefmt='%H:%M:%S')
