import modules
import threading
import time
import sys

def main():
    try:
        modules.HostDiscovery({}).execute()    
        # Blocking to see discovery output
        while(True): 
            time.sleep(1)
    except KeyboardInterrupt:
        print('User stopped kubehunter')
        sys.exit(1)

if __name__ == '__main__':
    main()