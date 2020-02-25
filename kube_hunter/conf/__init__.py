import logging
from kube_hunter.conf.parser import parse_args

config = parse_args()

loglevel = getattr(logging, config.log.upper(), None)

if not loglevel:
    logging.basicConfig(level=logging.INFO,
                        format='%(message)s',
                        datefmt='%H:%M:%S')
    logging.warning('Unknown log level selected, using info')
elif config.log.lower() != "none":
    logging.basicConfig(level=loglevel,
                        format='%(message)s',
                        datefmt='%H:%M:%S')

import plugins
