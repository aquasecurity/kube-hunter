#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter, Hunter for weak Kubernetes cluster')
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--remote', nargs='+', metavar="HOST", help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are:\nDEBUG INFO WARNING")
args = parser.parse_args()
try:
    loglevel = getattr(logging, args.log.upper())
except:
    pass
logging.basicConfig(level=loglevel, format='%(asctime)s - [%(levelname)s]: %(message)s')

import log
# executes all registrations from sub packages
import src.modules
from src.modules.discovery import HostDiscovery
from src.core.events import handler
from src.modules.discovery.hosts import HostScanEvent

def main():
    logging.info("Started")
    try:
        handler.publish_event(HostScanEvent(pod=args.pod, active=args.active, predefined_hosts=args.remote))
        # Blocking to see discovery output
        while(True): 
            time.sleep(100)
    except KeyboardInterrupt:
        logging.info("Kube-Hunter Stopped")        
    finally:
        handler.free()
        logging.debug("Cleaned Queue")        
        log.print_results(args.active)

if __name__ == '__main__':
    main()
