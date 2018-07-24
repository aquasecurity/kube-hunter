#!/bin/env python
import argparse
import logging

import sys
import time

parser = argparse.ArgumentParser(description='Kube-Hunter - hunts for security weaknesses in Kubernetes clusters')
parser.add_argument('--internal', action="store_true", help="set hunting of allinternal network interfaces")
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--cidr', type=str, help="set manual cidr to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")
import plugins

config = parser.parse_args()

try:
    loglevel = getattr(logging, config.log.upper())
except:
    pass
if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(message)s', datefmt='%H:%M:%S')

from src.core.events import handler
from src.core.events.types import HuntFinished, HuntStarted
from src.modules.discovery import HostDiscovery
from src.modules.discovery.hosts import HostScanEvent
import src


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = {
        "Remote scanning": "scans one or more specific IPs or DNS names",
        "Internal scanning": "scans all network interfaces",
        "CIDR scanning": "scans a specific CIDR"
    } # maps between option and its explanation
    
    print "Choose one of the options below:"
    for i, (option, explanation) in enumerate(options.items()):
        print "{}. {} ({})".format(i+1, option.ljust(20), explanation)
    choice = raw_input("Your choice: ")    
    if choice == '1':
        config.remote = raw_input("Remotes (separated by a ','): ").replace(' ', '').split(',')
    elif choice == '2':
        config.internal = True
    elif choice == '3': 
        config.cidr = raw_input("CIDR (example - 192.168.1.0/24): ").replace(' ', '')
    else: 
        return False
    return True

hunt_started = False
def main():
    global hunt_started 
    scan_options = [
        config.pod, 
        config.cidr,
        config.remote, 
        config.internal
    ]
    try:
        if not any(scan_options):
            if not interactive_set_config(): return
        
        hunt_started = True
        handler.publish_event(HuntStarted())
        handler.publish_event(HostScanEvent())
        
        # Blocking to see discovery output
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")
    finally:
        if hunt_started:
            handler.publish_event(HuntFinished())
            handler.join()
            handler.free()
            logging.debug("Cleaned Queue")

    if config.pod:
        while True: time.sleep(5)

if __name__ == '__main__':
    main()