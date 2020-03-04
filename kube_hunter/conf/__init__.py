import logging
from sys import stdout

from kube_hunter.conf.parser import parse_args

config = parse_args()

root = logging.getLogger()

handler = logging.StreamHandler(stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

loglevel = getattr(logging, config.log.upper(), None)

if not loglevel:
    handler.setLevel(logging.INFO)
    root.addHandler(handler)
    root.info('Unknown log level selected, using info')
else:
    handler.setLevel(loglevel)
    root.addHandler(handler)

import plugins
