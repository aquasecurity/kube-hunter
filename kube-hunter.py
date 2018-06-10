#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter, Hunter for weak Kubernetes cluster')
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are:\nDEBUG INFO WARNING")
parser.add_argument('--pod', action="store_true", help="When set, will scan the cluster as a pod, when unset, will scan all network interfaces")
args = parser.parse_args()
try:
    loglevel = getattr(logging, args.log.upper())
except:
    pass
logging.basicConfig(level=loglevel, format='%(asctime)s - [%(levelname)s]: %(message)s')

import log
# executes all registrations from sub packages
import modules
from modules.discovery import HostDiscovery
from modules.events import handler
from modules.discovery.hosts import HostScanEvent

def main():
    logging.info("Started")
    try:
        handler.publish_event(HostScanEvent(pod=args.pod, active=True))
        # Blocking to see discovery output
        while(True): 
            time.sleep(100)
    except KeyboardInterrupt:
        logging.info("Kube-Hunter Stopped")        
    finally:
        handler.free()
        logging.debug("Cleaned Queue")        
        log.print_results()

if __name__ == '__main__':
    main()
