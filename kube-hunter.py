#!/bin/env python
import logging
import sys
import time

import log

# executes all registrations from sub packages
import modules

from modules.discovery import HostDiscovery
from modules.events import handler
from modules.events.types import HostScanEvent


def main():
    logging.info("Started")
    try:
        handler.publish_event(HostScanEvent(interal=True, localhost=False))
        # Blocking to see discovery output
        while(True): 
            time.sleep(100)
    except KeyboardInterrupt:
        logging.info("Kube-Hunter Stopped")        
    finally:
        handler.free()
        logging.debug("Cleaned Queue")        

if __name__ == '__main__':
    main()
