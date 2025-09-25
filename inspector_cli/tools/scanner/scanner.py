import builtins
print = builtins.print
import sys
import socket
import re
import os
import concurrent.futures
from colorama import Fore, Style
import ssl



portlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "full_port_list.txt")

# Retrieves descriptive information about a given port from full_port_list.txt
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

# Mapping of specific ports to protocol-specific probe payloads and SSL requirements
PROTOCOL_PROBES = {
    21: (b"\r\n", False),                             # FTP
    22: (None, False),                                # SSH
    23: (b"\r\n", False),                             # Telnet
    25: (b"EHLO inspeector.local\r\n", False),        # SMTP
    80: (b"HEAD / HTTP/1.0\r\n\r\n", False),          # HTTP
    110: (b"\r\n", False),                            # POP3
    143: (b"\r\n", False),                            # IMAP
    443: (b"HEAD / HTTP/1.0\r\n\r\n", True),          # HTTPS
    465: (b"EHLO inspector.local\r\n", True),         # SMTPS
    993: (b"\r\n", True),                             # IMAPS
    995: (b"\r\n", True),                             # POP3S
    8443: (b"HEAD / HTTP/1.0\r\n\r\n", True),         # HTTPS-alt
    3306: (None, False),                              # MySQL
    3389: (None, False)                               # RDP
}

# Main class responsible for scanning ports on a target machine
class PortScanner:
    def __init__(self, settings, target=None):
        self.settings = settings
        self.target = target
        self.max_threads = int(self.settings["scanner"]["max_threads"])
        self.original_input = None
    # FIXED: Properly pass self.original_input to both re.match() calls
    def is_valid_input(self):
        ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        hostname_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        return bool(
            re.match(ipv4_pattern, self.original_input) or
            re.match(hostname_pattern, self.original_input)
        )

    # Checks if a single port is open, attempts banner grabbing, and prints port info
    def check_port(self, port):
        probe, use_ssl = PROTOCOL_PROBES.get(port, (None, False))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(self.settings["scanner"]["timeout"]))
            result = s.connect_ex((self.target, port))

            if result != 0:
                s.close()
                return  # Port is closed

            output = f"{Fore.GREEN}[OPEN] Port: {port}{Style.RESET_ALL}\n"

            if use_ssl:
                context = ssl.create_default_context()
                try:
                    s = context.wrap_socket(s, server_hostname=self.original_input)
                except Exception as e:
                    output += f"{Fore.RED}  ├─ SSL handshake failed: {e}{Style.RESET_ALL}\n"

                    info = port_info(port)
                    if info:
                        output += f"{Fore.CYAN}"
                        for line in info.splitlines():
                            output += f"  ├─ {line}\n"
                        output += f"{Style.RESET_ALL}"
                    else:
                        output += f"{Fore.LIGHTBLACK_EX}  └─ Info: No known description in portlist{Style.RESET_ALL}\n"

                    print(output, log=True)
                    s.close()
                    return



            # Attempt banner grabbing if probe defined
            banner = ""
            if probe:
                try:
                    s.sendall(probe)
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception as e:
                    banner = f"{Fore.RED}[!] Error receiving banner: {e}{Style.RESET_ALL}"
            else:
                banner = f"{Fore.YELLOW}[!] No probe sent; banner unlikely for this protocol.{Style.RESET_ALL}"

            output += f"{Fore.MAGENTA}  ├─ Banner: {banner}{Style.RESET_ALL}\n"

            info = port_info(port)
            if info:
                output += f"{Fore.CYAN}"
                for line in info.splitlines():
                    output += f"  ├─ {line}\n"
                output += f"{Style.RESET_ALL}"
            else:
                output += f"{Fore.LIGHTBLACK_EX}  └─ Info: No known description in portlist{Style.RESET_ALL}\n"

            print(output, log=True)
            s.close()

        except Exception as e:
            print(f"{Fore.RED}[!] Unexpected error on port {port}: {e}{Style.RESET_ALL}", log=True)


    # Prompts user for target IP/hostname and initiates full port scan using threading
    def scan_port(self, user_input):
        while True:
            self.original_input = user_input
            if not self.is_valid_input():
                print(f"{Fore.YELLOW}[?] Invalid input. Please enter a valid IPv4 address or hostname.{Style.RESET_ALL}")
                continue
            try:
                self.target = socket.gethostbyname(self.original_input)
                print(f"Your target is: {self.target}", log=True)
                break
            except socket.gaierror:
                print(f"{Fore.YELLOW}[?] Invalid IP or hostname. Try again:{Style.RESET_ALL}")
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future = executor.map(self.check_port,
                range(
                    int(self.settings["scanner"]["start_port"]),
                    int(self.settings["scanner"]["end_port"])
                ))
                for _ in future:
                    pass  # ensures KeyboardInterrupt gets caught here
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Scan interrupted by user. Exiting cleanly...{Style.RESET_ALL}")
            return  




