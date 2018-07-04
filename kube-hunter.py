#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter, Hunter for weak Kubernetes clusters. At the end of the hunt, a report will be printed to your screen.')
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod in cluster")
parser.add_argument('--internal', action="store_true", help="set hunting of all internal network interfaces")
parser.add_argument('--cidr', type=str, help="set manual cidr to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")
parser.add_argument('--token', type=str, metavar="AQUA_TOKEN", help="specify the token retrieved from Aqua, after finished executing, the report will be visible on kube-hunter's site")

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


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = {
        "Remote scanning": "scans one or more specific IPs or DNS names",
        "Internal scanning": "scans all network interfaces",
        "CIDR scanning": "scans a spesific cidr"
    } # maps between option and its explanation
    
    print "Choose one of the options below:"
    for i, (option, explanation) in enumerate(options.items()):
        print "{}. {} ({})".format(i+1, option.ljust(20), explanation)
    choice = raw_input("Your choice: ")    
    if choice == '1':
        config.remote = raw_input("Remotes (seperated by a ','): ").replace(' ', '').split(',')
    elif choice == '2':
        config.internal = True
    elif choice == '3': 
        config.cidr = raw_input("CIDR (example - 192.168.1.0/24): ").replace(' ', '')
    else: 
        return False
    return True

def main():
    scan_options = [
        config.pod, 
        config.cidr,
        config.remote, 
        config.internal
    ]
    hunt_started = False
    try:
        if not any(scan_options):
            if not interactive_set_config(): return
        hunt_started = True
        logging.info("Started")
        handler.publish_event(HostScanEvent())
        
        # Blocking to see discovery output
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")        
    finally:
        if hunt_started:
            handler.free()
            logging.debug("Cleaned Queue")        
            if config.token:
                reporter.send_report(token=config.token)
            else:
                reporter.print_tables()
        
    if config.pod:
        while True: time.sleep(5)

if __name__ == '__main__':
    main()