#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter, Hunter for weak Kubernetes clusters. By default, with no special arguments, Kube Hunter will scan all network interfaces for existing Kubernetes clusters. At the end of the hunt, a report will be printed to your screen.')
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod in cluster")
parser.add_argument('--container', action="store_true", help="set hunting from a container")
parser.add_argument('--cidr', type=str, help="set manual cidr to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")

config = parser.parse_args()
try:
    loglevel = getattr(logging, config.log.upper())
except:
    pass
if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(asctime)s - [%(levelname)s]: %(message)s')

from report import reporter
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
        reporter.print_tables()
        
    if config.pod:
        while True: time.sleep(5)

if __name__ == '__main__':
    main()


# Proof -> Evidence