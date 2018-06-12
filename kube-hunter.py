#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter, Hunter for weak Kubernetes cluster')
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are:\nDEBUG INFO WARNING")
config = parser.parse_args()
try:
    loglevel = getattr(logging, config.log.upper())
except:
    pass
logging.basicConfig(level=loglevel, format='%(asctime)s - [%(levelname)s]: %(message)s')

import log
from src.core.events import handler
from src.modules.discovery import HostDiscovery
from src.modules.discovery.hosts import HostScanEvent

def main():
    logging.info("Started")
    try:
        handler.publish_event(HostScanEvent(predefined_hosts=config.remote))
        # Blocking to see discovery output
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")        
    finally:
        handler.free()
        logging.debug("Cleaned Queue")        
        log.print_results(config.active)

if __name__ == '__main__':
    main()


# Proof -> Evidence