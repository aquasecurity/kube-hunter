#!/usr/bin/env python3
# flake8: noqa: E402

import logging
import threading

from kube_hunter.conf import Config, set_config
from kube_hunter.conf.parser import parse_args
from kube_hunter.conf.logging import setup_logger

from kube_hunter.plugins import initialize_plugin_manager

pm = initialize_plugin_manager()
# Using a plugin hook for adding arguments before parsing
args = parse_args(add_args_hook=pm.hook.parser_add_arguments)
config = Config(
    active=args.active,
    cidr=args.cidr,
    include_patched_versions=args.include_patched_versions,
    interface=args.interface,
    log_file=args.log_file,
    mapping=args.mapping,
    network_timeout=args.network_timeout,
    pod=args.pod,
    quick=args.quick,
    remote=args.remote,
    statistics=args.statistics,
    k8s_auto_discover_nodes=args.k8s_auto_discover_nodes,
    kubeconfig=args.kubeconfig,
)
setup_logger(args.log, args.log_file)
set_config(config)

# Running all other registered plugins before execution
pm.hook.load_plugin(args=args)

from kube_hunter.core.events import handler
from kube_hunter.core.events.types import HuntFinished, HuntStarted
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent
from kube_hunter.modules.report import get_reporter, get_dispatcher

logger = logging.getLogger(__name__)
config.dispatcher = get_dispatcher(args.dispatch)
config.reporter = get_reporter(args.report)


def interactive_set_config():
    """Sets config manually, returns True for success"""
    options = [
        ("Remote scanning", "scans one or more specific IPs or DNS names"),
        ("Interface scanning", "scans subnets on all local network interfaces"),
        ("IP range scanning", "scans a given IP range"),
    ]

    print("Choose one of the options below:")
    for i, (option, explanation) in enumerate(options):
        print("{}. {} ({})".format(i + 1, option.ljust(20), explanation))
    choice = input("Your choice: ")
    if choice == "1":
        config.remote = input("Remotes (separated by a ','): ").replace(" ", "").split(",")
    elif choice == "2":
        config.interface = True
    elif choice == "3":
        config.cidr = (
            input("CIDR separated by a ',' (example - 192.168.0.0/16,!192.168.0.8/32,!192.168.1.0/24): ")
            .replace(" ", "")
            .split(",")
        )
    else:
        return False
    return True


def list_hunters():
    print("\nPassive Hunters:\n----------------")
    for hunter, docs in handler.passive_hunters.items():
        name, doc = hunter.parse_docs(docs)
        print(f"* {name}\n  {doc}\n")

    if config.active:
        print("\n\nActive Hunters:\n---------------")
        for hunter, docs in handler.active_hunters.items():
            name, doc = hunter.parse_docs(docs)
            print(f"* {name}\n  {doc}\n")


hunt_started_lock = threading.Lock()
hunt_started = False


def main():
    global hunt_started
    scan_options = [config.pod, config.cidr, config.remote, config.interface, config.k8s_auto_discover_nodes]
    try:
        if args.list:
            list_hunters()
            return

        if not any(scan_options):
            if not interactive_set_config():
                return

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
        logger.debug("Kube-Hunter stopped by user")
    # happens when running a container without interactive option
    except EOFError:
        logger.error("\033[0;31mPlease run again with -it\033[0m")
    finally:
        hunt_started_lock.acquire()
        if hunt_started:
            hunt_started_lock.release()
            handler.publish_event(HuntFinished())
            handler.join()
            handler.free()
            logger.debug("Cleaned Queue")
        else:
            hunt_started_lock.release()


if __name__ == "__main__":
    main()
