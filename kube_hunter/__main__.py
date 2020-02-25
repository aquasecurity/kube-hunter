#!/usr/bin/env python3

import logging
import threading

from kube_hunter.conf import config
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import HuntFinished, HuntStarted
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent
from kube_hunter.modules.report import get_reporter, get_dispatcher

config.reporter = get_reporter(config.report)
config.dispatcher = get_dispatcher(config.dispatch)

import kube_hunter


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = [("Remote scanning",
                "scans one or more specific IPs or DNS names"),
               ("Interface scanning",
                "scans subnets on all local network interfaces"),
               ("IP range scanning", "scans a given IP range")]

    print("Choose one of the options below:")
    for i, (option, explanation) in enumerate(options):
        print("{}. {} ({})".format(i+1, option.ljust(20), explanation))
    choice = input("Your choice: ")
    if choice == '1':
        config.remote = input("Remotes (separated by a ','): ").\
            replace(' ', '').split(',')
    elif choice == '2':
        config.interface = True
    elif choice == '3':
        config.cidr = input("CIDR (example - 192.168.1.0/24): ").\
            replace(' ', '')
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
