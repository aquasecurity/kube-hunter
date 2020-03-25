import logging

from kube_hunter.conf.parser import parse_args

def setup_logger(log_level_name):
    formatter = '%(asctime)s %(levelname)s %(name)s %(message)s'
    if log_level_name == "NONE":
        logging.disable(logging.CRITICAL)
    else:
        log_level = getattr(logging, log_level_name, None)
        if not log_level:
            log_level = logging.INFO
            logging.warning("Unknown log level selected, using INFO")
        logging.basicConfig(level=log_level_name, format=formatter)

config = parse_args()
log_level_name = config.log.upper()
setup_logger(log_level_name)

import plugins
