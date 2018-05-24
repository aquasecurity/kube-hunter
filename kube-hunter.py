#!/bin/env python
import log

from events import handler, HostScanEvent
from discovery import HostDiscovery
import hunting
import time
import sys
import logging

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