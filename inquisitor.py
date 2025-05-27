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
print("Version 0.1.5")
print("-" * 50)

scanner_instance = scanner.PortScanner()



def tool():
    mode = input("Pick the tool you wanna use: \n 1. Port Scanner\n")
    if mode == 1 or "Port Scanner":
        try:
            scanner_instance.scan_port()

        except KeyboardInterrupt:
            print("Shutting down")

tool()
