#! /usr/bin/python

from __future__ import print_function

from argparse import ArgumentParser
from logging import DEBUG, basicConfig, info, warning

from discovery import DEFAULT_PORTS, HostScanner
from hunters import Dashboard, Kubelet, Proxy
from services import *
from validation import ip, subnet

HUNT_MODE = "hunt"
SCAN_MODE = "scan"


def hunt_callback(host):
    hunters = {
        KUBERNETES_DASHBOARD: Dashboard,
        KUBERNETES_KUBELET_HTTPS: Kubelet,
        KUBERNETES_KUBELET_HTTP: Kubelet,
        KUBERNETES_PROXY: Proxy
    }

    service_type = identify_service(host)
    if service_type == UNKNOWN:
        return

    if service_type not in hunters:
        warning("Unsupported service type: {}".format(describe_service_type(service_type)))
    else:
        hunters[service_type]().hunt(host)


def scan_callback(host):
    print("{} - {}".format(host, describe_service_type(identify_service(host))))


def hunt(*args, **kwargs):
    target = args[0]
    info("Hunting target {}".format(target))
    # scanner = HostScanner(threads=1)
    # scanner.scan(target, DEFAULT_PORTS, hunt_callback)


def scan(*args, **kwargs):
    target = args[0]
    info("Scanning for targets on {}".format(target))
    scanner = HostScanner(threads=20)
    scanner.scan(target, DEFAULT_PORTS, scan_callback)


def main(mode, *args, **kwargs):
    actions = {
        SCAN_MODE: scan,
        HUNT_MODE: hunt
    }

    actions[mode](*args, **kwargs)


if __name__ == "__main__":
    basicConfig(level=DEBUG)
    parser = ArgumentParser()

    subparsers = parser.add_subparsers(dest="action", description="Available actions")

    hunt_parser = subparsers.add_parser(HUNT_MODE)
    hunt_parser.add_argument("host", type=ip, help="host to hunt")

    scan_parser = subparsers.add_parser(SCAN_MODE)
    scan_parser.add_argument("subnet", type=subnet, help="subnet to scan (CIDR notation)")

    arguments = parser.parse_args()

    main(arguments.action, *([i[1] for i in arguments._get_kwargs()[1:]]))
