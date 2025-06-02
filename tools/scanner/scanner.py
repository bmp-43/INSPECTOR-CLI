import sys
import socket
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

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
config_path = os.path.join(base_dir, "config", "config_inquisitor.txt")

if not os.path.isfile(config_path):
    print(f"Config file not found at: {config_path}")
    sys.exit(1)
settings = config(config_path)
portlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "full_port_list.txt")




def port_info(port):
    port = str(port)
    info_lines = []
    found = False
    try:
        with open(portlist_path, "r") as file:
            for line in file:
                if line.startswith(f"Port: {port}"):
                    found = True
                    info_lines.append(line.strip())
                    continue
                if found:
                    if line.startswith("Port: "):
                        break
                    if line.strip() == "":
                        continue
                    info_lines.append(line.strip())
    except FileNotFoundError:
        return None
    return "\n".join(info_lines) if info_lines else None
    




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
        s.settimeout(float(settings.get("timeout_scanner", 0.5)))
        result = s.connect_ex((self.target, port))
        if result == 0:
            print(f"Port {port} is open")
            info = port_info(port)
            if info:
                print(info)
            print()
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


scan = PortScanner()

try:
    if __name__ == "__main__":
        scan.scan_port()

except KeyboardInterrupt:
    print("SHUTTING DOWN")

 
