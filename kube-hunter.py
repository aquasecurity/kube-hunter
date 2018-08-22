#!/usr/bin/env python
from __future__ import print_function

import argparse
import logging

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

parser = argparse.ArgumentParser(description='Kube-Hunter - hunts for security weaknesses in Kubernetes clusters')
parser.add_argument('--list', action="store_true", help="displays all tests in kubehunter (add --active flag to see active tests)")
parser.add_argument('--internal', action="store_true", help="set hunting of all internal network interfaces")
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--cidr', type=str, help="set an ip range to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")
parser.add_argument('--report', type=str, default='plain', help="set report type, options are: plain, yaml")

import plugins

config = parser.parse_args()

try:
    loglevel = getattr(logging, config.log.upper())
except:
    pass
if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(message)s', datefmt='%H:%M:%S')

from src.modules.report.plain import PlainReporter
from src.modules.report.yaml import YAMLReporter

if config.report.lower() == "yaml":
    config.reporter = YAMLReporter()
else:
    config.reporter = PlainReporter()

from src.core.events import handler
from src.core.events.types import HuntFinished, HuntStarted
from src.modules.discovery import HostDiscovery
from src.modules.discovery.hosts import HostScanEvent
import src


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = [("Remote scanning", "scans one or more specific IPs or DNS names"),
    ("Subnet scanning","scans subnets on all local network interfaces"),
    ("IP range scanning","scans a given IP range")]
    
    print("Choose one of the options below:")
    for i, (option, explanation) in enumerate(options):
        print("{}. {} ({})".format(i+1, option.ljust(20), explanation))
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

def parse_docs(hunter, docs):
    """returns tuple of (name, docs)"""
    if not docs:
        return hunter.__name__, "<no documentation>" 
    docs = docs.strip().split('\n')
    for i, line in enumerate(docs):
        docs[i] = line.strip()
    return docs[0], ' '.join(docs[1:]) if len(docs[1:]) else "<no documentation>"
    
def list_hunters():
    print("\nPassive Hunters:\n----------------")
    for i, (hunter, docs) in enumerate(handler.passive_hunters.items()):
        name, docs = parse_docs(hunter, docs)
        print("* {}\n  {}\n".format( name, docs))

    if config.active:
        print("\n\nActive Hunters:\n---------------")
        for i, (hunter, docs) in enumerate(handler.active_hunters.items()):
            name, docs = parse_docs(hunter, docs)
            print("* {}\n  {}\n".format( name, docs))
        

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
        if config.list:
            list_hunters()
            return

        if not any(scan_options):
            if not interactive_set_config(): return
        
        hunt_started = True
        handler.publish_event(HuntStarted())
        handler.publish_event(HostScanEvent())
        
        # Blocking to see discovery output
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")
    # happens when running a container without interactive option
    except EOFError:
        logging.error("\033[0;31mPlease run again with -it\033[0m")
    finally:
        if hunt_started:
            handler.publish_event(HuntFinished())
            handler.join()
            handler.free()
            logging.debug("Cleaned Queue")

if __name__ == '__main__':
    main()
