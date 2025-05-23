import pyfiglet
import sys
import socket
from datetime import datetime
import re
import os
import concurrent.futures


print("-" * 50)


def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # Go up one level from tools
config_path = os.path.join(base_dir, "config", "config_inquisitor.txt")
settings = config(config_path)


class PortScanner:
    def __init__(self, target=None, max_threads=int(settings.get("max_threads", 100))):
        self.target = target
        self.max_threads = max_threads

    def is_valid_input(self, user_input):
        ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        hostname_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        return bool(re.match(ipv4_pattern, user_input) or re.match(hostname_pattern, user_input))

    def check_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(settings.get("timeout", 0.5)))
        result = s.connect_ex((self.target, port))
        if result == 0:
            print(f"Port {port} is open")
        s.close()

    def scan_port(self):
        while True:
            user_input = input("Enter target IP address: ")
            if not self.is_valid_input(user_input):
                print("Invalid input. Please enter a valid IPv4 address or hostname.")
                continue
            try:
                self.target = socket.gethostbyname(user_input)
                print(f"Your target is: {self.target}")
                break
            except socket.gaierror:
                print("Invalid IP or hostname. Try again:")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(
                self.check_port,
                range(int(settings.get("start_port", 1)), int(settings.get("end_port", 65535)))
            )


test = PortScanner()

try:
    if __name__ == "__main__":
        test.scan_port()

except KeyboardInterrupt:
    print("SHUTTING DOWN")

 
