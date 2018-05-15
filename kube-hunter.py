import log

from events import handler
import discovery
import hunting
import time
import sys
import logging

def main():
    logging.info("Started")
    try:
        discovery.HostDiscovery({}).execute()    
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