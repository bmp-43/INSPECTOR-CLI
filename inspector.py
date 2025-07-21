import pyfiglet
from colorama import Fore, Style
from tools.scanner import scanner
from tools.enumerator import enumerator
from tools.analyser import analyser
from tools.profiler import profiler
import os
import sys

# Separator line using blue dashes for consistent styling
separators = f"{Fore.BLUE}-{Style.RESET_ALL}" * 50

# Print ASCII banner and version
print(separators)
ascii_banner = pyfiglet.figlet_format("INSPECTOR")
print(f"{Fore.BLUE}{ascii_banner}")
print(f"Version 0.4.3 BETA{Style.RESET_ALL}")
print(separators)

# Info message about threading-related warnings in Python 3.13
print(f"{Style.RESET_ALL}I would like to inform you that if you launch tools separately not as its intended random tracebacks may appear.\nIgnore it — Python 3.13 threading cleanup is noisy. Not your fault. And neither is mine :3{Fore.BLUE}")

# Load config.txt values into a dictionary
def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

# Set base config path and verify config exists
base_dir = os.path.dirname((os.path.abspath(__file__)))
config_path = os.path.join(base_dir, "config", "config.txt")
if not os.path.isfile(config_path):
    print(f"{Fore.RED}[!] Config file not found at: {config_path}{Style.RESET_ALL}")
    sys.exit(1)

# Load configuration values
settings = config(config_path)

# Initialize the PortScanner instance once
scanner_instance = scanner.PortScanner()

# Main interactive menu
def weapon():
    print(separators)
    mode = input(f"{Style.RESET_ALL}Pick the tool you wanna use: \n 1. Port Scanner\n 2. Malware Analyser \n 3. Recon & OSINT\n")
    print(separators)

    # Option 1 — Port Scanner
    if mode == "1" or mode.lower() == "port scanner":
        try:
            scanner_instance.scan_port()
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Port Scanner Error: {e}{Style.RESET_ALL}")

    # Option 2 — Malware Analyser
    elif mode == "2" or mode.lower() == "malware analyser":
        try:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Note that Malware analyser uses VirusTotal API. Check the config.txt{Style.RESET_ALL}")
            print(separators)
            analyser.main()
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}") 
        except Exception as e:
            print(f"{Fore.RED}[!] Malware Analyser Error: {e}{Style.RESET_ALL}")
    
    # Option 3 — Recon & OSINT Menu
    elif mode == "3" or mode.lower() == "recon & osint":
        try:
            print(separators)
            osint_tool = input("Pick your Recon tool \n 1. Subdomain Enumerator \n 2. Directory Brute-Forcer \n 3. DNS Profiler\n")
            print(separators)

            # Subdomain Enumerator
            if osint_tool == "1" or osint_tool.lower() == "subdomain enumerator":
                try:
                    enumerator.subdomain_enum()
                except Exception as e:
                    print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")

            # Directory Brute-Forcer
            elif osint_tool == "2" or osint_tool.lower() == "directory brute-forcer":
                try:
                    enumerator.directory_brute_force()
                except Exception as e:
                    print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")

            # DNS Profiler
            elif osint_tool == "3" or osint_tool.lower() == "dns profiler":
                try:
                    print(separators)
                    initializator=profiler.Profiler(domain=input("Enter domain name: "))
                    initializator.domain_lookup()
                    initializator.dns_records_fetching()
                    initializator.ip_lookup()
                    initializator.reverse_dns()
                    initializator.result()
                except Exception as e:
                    print(f"{Fore.RED}[!] Profiler Error: {e}{Style.RESET_ALL}")
            
            # Invalid OSINT subtool selection
            else:
                print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")   
    
    # Invalid main menu selection
    else:
        print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")         

# Loop the tool selector until interrupted
try:
    while True:
        weapon()
except KeyboardInterrupt:
    print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
