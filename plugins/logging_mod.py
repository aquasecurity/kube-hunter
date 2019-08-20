import logging

# Supress logging from scapy
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)

# supress general python warnings
import warnings
warnings.filterwarnings("ignore")