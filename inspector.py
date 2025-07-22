import builtins
import os
import atexit
import re
from datetime import datetime
import pyfiglet
from colorama import Fore, Style
import os
import sys

original_print = builtins.print

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

#Decide if logging stays
logging_state = str(settings.get("logging_enabled", "True"))
# Initialize the PortScanner instance once
th_warning = False
def main_launching():
    global scanner, enumerator, analyser, profiler
    from tools.scanner import scanner
    from tools.enumerator import enumerator
    from tools.analyser import analyser
    from tools.profiler import profiler
    global scanner_instance
    scanner_instance = scanner.PortScanner()
    # Info message about threading-related warnings in Python 3.13
    print(f"{Style.RESET_ALL}I would like to inform you that if you launch tools separately not as its intended random tracebacks may appear.\nIgnore it — Python 3.13 threading cleanup is noisy. Not your fault. And neither is mine :3{Fore.BLUE}")
    global th_warning
    th_warning = True




# Main interactive menu
def weapon():
    # Separator line using blue dashes for consistent styling
    separators = f"{Fore.BLUE}-{Style.RESET_ALL}" * 50

    # Print ASCII banner and version
    print(separators, log=True)
    ascii_banner = pyfiglet.figlet_format("INSPECTOR")
    print(f"{Fore.BLUE}{ascii_banner}", log=True)
    print(f"Version 0.4.3 BETA{Style.RESET_ALL}", log=True)
    print(separators, log=True)
    if th_warning == False:
        main_launching()
    else:
        pass

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
            
            # Invalid tool selection
            else:
                print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")   
    
    # Invalid main menu selection
    else:
        print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")         

logging_module = False
def saving_prep():
    global ansi_escape
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    global original_print
    # Save the original print
    original_print = builtins.print
    global logging_module
    logging_module = True

def custom_print_true(*args, **kwargs):
    log = kwargs.pop("log", False)
    original_print(*args, **kwargs)
    if log:
        text = ' '.join(str(arg) for arg in args)
        cleaned = ansi_escape.sub('', text)
        output_file.write(cleaned + '\n')
        output_file.flush()

def custom_print_false(*args, **kwargs):
    # Remove 'log' if present, do nothing with it if logging is off
    kwargs.pop("log", None)
    original_print(*args, **kwargs)

# Loop the tool selector until interrupted
try:
    while True:
        # Prepare output file
        if logging_state == "True":
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            output_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results/INSPECTOR_RESULTS_{timestamp}.txt")
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
            output_file = open(output_file_path, "w", encoding="utf-8")
        else:
            pass
        if logging_module == False and logging_state == "True":
            saving_prep()
            builtins.print = custom_print_true
            # Ensure file gets closed
            atexit.register(output_file.close)
        else:
            builtins.print = custom_print_false
        weapon()
except KeyboardInterrupt:
    print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")