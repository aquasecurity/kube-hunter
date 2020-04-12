import logging


DEFAULT_LEVEL = logging.INFO
DEFAULT_LEVEL_NAME = logging.getLevelName(DEFAULT_LEVEL)
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# Suppress logging from scapy
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)


def setup_logger(level_name):
    # Remove any existing handlers
    # Unnecessary in Python 3.8 since `logging.basicConfig` has `force` parameter
    for h in logging.getLogger().handlers[:]:
        h.close()
        logging.getLogger().removeHandler(h)

    if level_name.upper() == "NONE":
        logging.disable(logging.CRITICAL)
    else:
        log_level = getattr(logging, level_name.upper(), None)
        log_level = log_level if type(log_level) is int else None
        logging.basicConfig(level=log_level or DEFAULT_LEVEL, format=LOG_FORMAT)
        if not log_level:
            logging.warning(f"Unknown log level '{level_name}', using {DEFAULT_LEVEL_NAME}")
