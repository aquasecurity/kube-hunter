#!/usr/bin/env python
import argparse
import logging
import threading


parser = argparse.ArgumentParser(description='Kube-Hunter - hunts for security weaknesses in Kubernetes clusters')
parser.add_argument('--list', action="store_true", help="displays all tests in kubehunter (add --active flag to see active tests)")
parser.add_argument('--interface', action="store_true", help="set hunting of all network interfaces")
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--quick', action="store_true", help="Prefer quick scan (subnet 24)")
parser.add_argument('--ignore-downstream', action="store_true", help="Ignore patched kubernetes versions")
parser.add_argument('--cidr', type=str, help="set an ip range to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")
parser.add_argument('--report', type=str, default='plain', help="set report type, options are: plain, yaml, json")
parser.add_argument('--dispatch', type=str, default='stdout', help="where to send the report to, options are: stdout, http (set KUBEHUNTER_HTTP_DISPATCH_URL and KUBEHUNTER_HTTP_DISPATCH_METHOD environment variables to configure)")
parser.add_argument('--statistics', action="store_true", help="set hunting statistics")
parser.add_argument('--infrastructure-check', action="store_true", help="whether to check if the cluster is deployed on azure cloud - defaults to true")

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
from src.modules.report.json_reporter import JSONReporter
reporters = {
    'yaml': YAMLReporter,
    'json': JSONReporter,
    'plain': PlainReporter
}
if config.report.lower() in reporters.keys():
    config.reporter = reporters[config.report.lower()]()
else:
    logging.warning('Unknown reporter selected, using plain')
    config.reporter = reporters['plain']()

from src.modules.report.dispatchers import STDOUTDispatcher, HTTPDispatcher
dispatchers = {
    'stdout': STDOUTDispatcher,
    'http': HTTPDispatcher
}
if config.dispatch.lower() in dispatchers.keys():
    config.dispatcher = dispatchers[config.dispatch.lower()]()
else:
    logging.warning('Unknown dispatcher selected, using stdout')
    config.dispatcher = dispatchers['stdout']()

from src.core.events import handler
from src.core.events.types import HuntFinished, HuntStarted
from src.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent
import src


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = [("Remote scanning", "scans one or more specific IPs or DNS names"),
    ("Interface scanning","scans subnets on all local network interfaces"),
    ("IP range scanning","scans a given IP range")]
    
    print("Choose one of the options below:")
    for i, (option, explanation) in enumerate(options):
        print("{}. {} ({})".format(i+1, option.ljust(20), explanation))
    choice = input("Your choice: ")
    if choice == '1':
        config.remote = input("Remotes (separated by a ','): ").replace(' ', '').split(',')
    elif choice == '2':
        config.interface = True
    elif choice == '3': 
        config.cidr = input("CIDR (example - 192.168.1.0/24): ").replace(' ', '')
    else: 
        return False
    return True


def list_hunters():
    print("\nPassive Hunters:\n----------------")
    for hunter, docs in handler.passive_hunters.items():
        name, doc = hunter.parse_docs(docs)
        print("* {}\n  {}\n".format(name, doc))

    if config.active:
        print("\n\nActive Hunters:\n---------------")
        for hunter, docs in handler.active_hunters.items():
            name, doc = hunter.parse_docs(docs)
            print("* {}\n  {}\n".format( name, doc))


global hunt_started_lock
hunt_started_lock = threading.Lock()
hunt_started = False


def main():
    global hunt_started
    scan_options = [
        config.pod, 
        config.cidr,
        config.remote, 
        config.interface
    ]
    try:
        if config.list:
            list_hunters()
            return

        if not any(scan_options):
            if not interactive_set_config(): return

        hunt_started_lock.acquire()
        hunt_started = True
        hunt_started_lock.release()
        handler.publish_event(HuntStarted())
        if config.pod:
            handler.publish_event(RunningAsPodEvent())
        else:
            handler.publish_event(HostScanEvent())
        
        # Blocking to see discovery output
        handler.join()
    except KeyboardInterrupt:
        logging.debug("Kube-Hunter stopped by user")
    # happens when running a container without interactive option
    except EOFError:
        logging.error("\033[0;31mPlease run again with -it\033[0m")
    finally:
        hunt_started_lock.acquire()
        if hunt_started:
            hunt_started_lock.release()
            handler.publish_event(HuntFinished())
            handler.join()
            handler.free()
            logging.debug("Cleaned Queue")
        else:
            hunt_started_lock.release()



if __name__ == '__main__':
        main()

