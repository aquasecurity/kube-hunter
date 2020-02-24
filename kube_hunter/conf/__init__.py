import logging
from kube_hunter.conf.parser import parse_args

config = parse_args()

loglevel = getattr(logging, config.log.upper(), logging.INFO)

if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(message)s',
                        datefmt='%H:%M:%S')
