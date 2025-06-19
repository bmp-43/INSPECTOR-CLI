import sys
import socket
import re
import os
import concurrent.futures
from colorama import Fore, Style
import ssl



def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
config_path = os.path.join(base_dir, "config", "config.txt")

if not os.path.isfile(config_path):
    print(f"{Fore.RED}Config file not found at: {config_path}{Style.RESET_ALL}")
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
    

PROTOCOL_PROBES = {
    21: (b"\r\n", False),                             # FTP
    22: (None, False),                                # SSH
    23: (b"\r\n", False),                             # Telnet
    25: (b"EHLO inspeector.local\r\n", False),        # SMTP
    80: (b"HEAD / HTTP/1.0\r\n\r\n", False),          # HTTP
    110: (b"\r\n", False),                            # POP3
    143: (b"\r\n", False),                            # IMAP
    443: (b"HEAD / HTTP/1.0\r\n\r\n", True),          # HTTPS
    465: (b"EHLO inspector.local\r\n", True),        # SMTPS
    993: (b"\r\n", True),                             # IMAPS
    995: (b"\r\n", True),                             # POP3S
    8443: (b"HEAD / HTTP/1.0\r\n\r\n", True),         # HTTPS-alt
    3306: (None, False),                              # MySQL
    3389: (None, False)                               # RDP
}




class PortScanner:
    def __init__(self, target=None, max_threads=int(settings.get("max_threads", 100))):
        self.target = target
        self.max_threads = max_threads

    def is_valid_input(self, user_input):
        ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        hostname_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        return bool(re.match(ipv4_pattern, user_input) or re.match(hostname_pattern, user_input))



    def check_port(self, port):
        probe, use_ssl = PROTOCOL_PROBES.get(port, (None, False))
        try:
            if use_ssl:
                context = ssl.create_default_context()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(float(settings.get("timeout_scanner", 0.5)))
                s = context.wrap_socket(s, server_hostname=self.target)
                result = s.connect_ex((self.target, port))
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(float(settings.get("timeout_scanner", 0.5)))
                result = s.connect_ex((self.target, port))

            if result == 0:
                print(f"{Fore.GREEN}Port {port} is open{Style.RESET_ALL}")
                banner = ""
                if probe:
                    try:
                        s.sendall(probe)
                        banner = s.recv(1024).decode(errors="ignore").strip()
                    except Exception as e:
                        print(f"{Fore.RED}[Banner on port {port}] Error receiving banner: {e}{Style.RESET_ALL}")
                else:
                    # For protocols that don't expect a probe, you may not get a banner at all
                    print(f"{Fore.YELLOW}[Banner on port {port}] No probe sent; banner unlikely for this protocol.{Style.RESET_ALL}")

                if banner:
                    print(f"{Fore.MAGENTA}[Banner on port {port}] {banner}{Style.RESET_ALL}")
                elif probe:
                    print(f"{Fore.RED}[Banner on port {port}] No banner received.{Style.RESET_ALL}")

                info = port_info(port)
                if info:
                    print(f"{Fore.CYAN}{info}{Style.RESET_ALL}")
                print()
            s.close()
        except Exception:
            print(f"{Fore.RED}[Banner on port {port}] Grab failed or timed out.\n{Style.RESET_ALL}")


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
        print(f"{Fore.BLUE}-" * 50)
        print(f"{Style.RESET_ALL}")
        scan.scan_port()
        
except KeyboardInterrupt:
    print("SHUTTING DOWN")

 
