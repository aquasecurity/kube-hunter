#!/usr/bin/env python3

import logging
import time

from typing import Sequence, Type
from kube_hunter.conf import Config, set_config
from kube_hunter.conf.logging import setup_logger
from kube_hunter.conf.parser import parse_args
from kube_hunter.core.events import HuntFinished, HuntStarted, ReportDispatched
from kube_hunter.core.types import HunterBase
from kube_hunter.core.pubsub.eventqueue import EventQueue
from kube_hunter.modules.discovery.all import all_discovery
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent
from kube_hunter.modules.hunting.all import active_hunters, all_hunters, passive_hunters
from kube_hunter.modules.report.collector import Collector
from kube_hunter.modules.report.factory import get_reporter, get_dispatcher

args = parse_args()
setup_logger(args.log)
config = Config(
    active=args.active,
    cidr=args.cidr.split(","),
    include_patched_versions=args.include_patched_versions,
    interface=args.interface,
    mapping=args.mapping,
    network_timeout=args.network_timeout,
    pod=args.pod,
    quick=args.quick,
    remote=args.remote,
    statistics=args.statistics,
)
set_config(config)

logger = logging.getLogger(__name__)


def interactive_set_config() -> bool:
    """Sets config manually, returns True for success"""
    options = [
        ("Remote scanning", "scans one or more specific IPs or DNS names"),
        ("Interface scanning", "scans subnets on all local network interfaces"),
        ("IP range scanning", "scans a given IP range"),
    ]

    print("Choose one of the options below:")
    for i, (option, explanation) in enumerate(options, start=1):
        print("{}. {} ({})".format(i, option.ljust(20), explanation))
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


def print_hunters(hunters: Sequence[Type[HunterBase]]):
    for hunter in hunters:
        header, description = hunter.parse_docs()
        print(f"* {header}\n  {description}\n")


def list_hunters():
    print("\nPassive Hunters:\n----------------")
    print_hunters(passive_hunters())

    if config.active:
        print("\n\nActive Hunters:\n---------------")
        print_hunters(active_hunters())


def publish_start_events(handler: EventQueue, from_pod: bool = False):
    handler.publish_event(HuntStarted())
    if from_pod:
        handler.publish_event(RunningAsPodEvent())
    else:
        handler.publish_event(HostScanEvent())


def main():
    if args.list:
        list_hunters()
        return

    if not any([config.pod, config.cidr, config.remote, config.interface]):
        if not interactive_set_config():
            return

    handler = EventQueue()
    for discovery in all_discovery():
        handler.register(discovery)

    hunters = all_hunters() if config.active else passive_hunters()
    for hunter in hunters:
        handler.register(hunter)

    handler.start()
    publish_start_events(handler, config.pod)

    try:
        while not handler.finished():
            time.sleep(2)
    except KeyboardInterrupt:
        logger.debug("Kube-Hunter stopped by user")
    except EOFError:
        logger.error("No tty set. If running in docker try using '-it' flags")
    finally:
        handler.publish_event(HuntFinished())
        handler.stop(wait=True)
        logger.debug("Event queue closed")

    dispatcher = get_dispatcher(args.dispatch)
    reporter = get_reporter(args.report)
    report = reporter.get_report(
        services=Collector.services,
        vulnerabilities=Collector.vulnerabilities,
        hunters=hunters,
        statistics=config.statistics,
        mapping=config.mapping,
    )
    dispatcher.dispatch(report)
    handler.publish_event(ReportDispatched())


if __name__ == "__main__":
    main()
