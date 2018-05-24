import logging
import argparse

parser = argparse.ArgumentParser(description='Kubehunter, hunting weak kubernetes clusters')
parser.add_argument('--log', type=str, metavar="LOGLEVEL", default='INFO', help="set output level, options are:\nDEBUG INFO WARNING")

args = parser.parse_args()
try:
    loglevel = getattr(logging, args.log.upper())
except:
    pass

logging.basicConfig(level=loglevel, format='%(asctime)s - [%(levelname)s]: %(message)s')
