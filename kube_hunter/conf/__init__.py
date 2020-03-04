import logging

from kube_hunter.conf.parser import parse_args

config = parse_args()
formatter = '%(asctime)s %(levelname)s %(name)s %(message)s'

loglevel = getattr(logging, config.log.upper(), None)

if not loglevel:
    logging.basicConfig(level=logging.INFO,
                        format=formatter)
    logging.warning('Unknown log level selected, using info')
elif config.log.lower() != "none":
    logging.basicConfig(level=loglevel,
                        format=formatter)

import plugins
