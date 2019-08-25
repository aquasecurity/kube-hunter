import logging

# Supress logging from scapy
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)
