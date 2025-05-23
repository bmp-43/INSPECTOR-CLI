import pyfiglet
import sys
import socket
from datetime import datetime
import re
import os
import concurrent.futures
from tools import scanner


ascii_banner = pyfiglet.figlet_format("INQUISITOR")
print(ascii_banner)
print("-" * 50)

scanner_instance = scanner.PortScanner()

try:
    scanner_instance.scan_port()

except KeyboardInterrupt:
    print("Shutting down")