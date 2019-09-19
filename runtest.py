import argparse
import pytest 

parser = argparse.ArgumentParser(description='Kube-Hunter tests')
parser.add_argument('--list', action="store_true", help="displays all tests in kubehunter (add --active flag to see active tests)")
parser.add_argument('--interface', action="store_true", help="set hunting of all interface network interfaces")
parser.add_argument('--pod', action="store_true", help="set hunter as an insider pod")
parser.add_argument('--quick', action="store_true", help="Prefer quick scan (subnet 24)")
parser.add_argument('--ignore-downstream', action="store_true", help="Ignore patched kubernetes versions")
parser.add_argument('--cidr', type=str, help="set an ip range to scan, example: 192.168.0.0/16")
parser.add_argument('--mapping', action="store_true", help="outputs only a mapping of the cluster's nodes")
parser.add_argument('--remote', nargs='+', metavar="HOST", default=list(), help="one or more remote ip/dns to hunt")
parser.add_argument('--active', action="store_true", help="enables active hunting")
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set log level, options are: debug, info, warn, none")
parser.add_argument('--report', type=str, default='plain', help="set report type, options are: plain, yaml")
parser.add_argument('--statistics', action="store_true", help="set hunting statistics")

config = parser.parse_args()

import tests

def main():
    exit(pytest.main(['.']))


if __name__ == '__main__':
    main()