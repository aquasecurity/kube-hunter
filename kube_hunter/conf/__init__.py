from kube_hunter.conf.parser import parse_args
from kube_hunter.conf.logging import setup_logger


config = parse_args()
setup_logger(config.log)

__all__ = [config]
