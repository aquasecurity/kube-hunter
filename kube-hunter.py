#!/usr/bin/env python3

import argparse
import logging
import threading

from src.conf import config
from src.modules.report.plain import PlainReporter
from src.modules.report.yaml import YAMLReporter
from src.modules.report.json import JSONReporter
from src.modules.report.dispatchers import STDOUTDispatcher, HTTPDispatcher
from src.core.events import handler
from src.core.events.types import HuntFinished, HuntStarted
from src.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent


# TODO: move log level parsing to conf module
loglevel = getattr(logging, config.log.upper(), logging.INFO)

# TODO: use --quiet flag for this logic
if config.log.lower() != "none":
    logging.basicConfig(level=loglevel, format='%(message)s', datefmt='%H:%M:%S')

# TODO: move this mapping to report module, consider using factory for abstraction
reporters = {
    'yaml': YAMLReporter,
    'json': JSONReporter,
    'plain': PlainReporter
}

# TODO: move report config handling to conf module
if config.report.lower() in reporters.keys():
    config.reporter = reporters[config.report.lower()]()
else:
    logging.warning('Unknown reporter selected, using plain')
    config.reporter = reporters['plain']()

# TODO: move this mapping to report module, consider using factory for abstraction
dispatchers = {
    'stdout': STDOUTDispatcher,
    'http': HTTPDispatcher
}

# TODO: move dispatch config handling to conf module
if config.dispatch.lower() in dispatchers.keys():
    config.dispatcher = dispatchers[config.dispatch.lower()]()
else:
    logging.warning('Unknown dispatcher selected, using stdout')
    config.dispatcher = dispatchers['stdout']()

# TODO: importing the root module is the way to subscribe events automatically
#       make an explicit behavior to do that
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
        
        with hunt_started_lock:
            hunt_started = True
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
