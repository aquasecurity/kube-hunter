import logging

DEFAULT_LEVEL = logging.INFO
DEFAULT_LEVEL_NAME = logging.getLevelName(DEFAULT_LEVEL)
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def setup_logger(level_name, logfile):
    # Remove any existing handlers
    # Unnecessary in Python 3.8 since `logging.basicConfig` has `force` parameter
    for h in logging.getLogger().handlers[:]:
        h.close()
        logging.getLogger().removeHandler(h)

    if level_name.upper() == "NONE":
        logging.disable(logging.CRITICAL)
    else:
        log_level = getattr(logging, level_name.upper(), None)
        log_level = log_level if isinstance(log_level, int) else None
        if logfile is None:
            logging.basicConfig(level=log_level or DEFAULT_LEVEL, format=LOG_FORMAT)
        else:
            logging.basicConfig(filename=logfile, level=log_level or DEFAULT_LEVEL, format=LOG_FORMAT)
        if not log_level:
            logging.warning(f"Unknown log level '{level_name}', using {DEFAULT_LEVEL_NAME}")
