import builtins
import os
import atexit
import re
from datetime import datetime
import pyfiglet
from colorama import Fore, Style
import sys
import signal


original_print = builtins.print
output_file = None
ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
separators = f"{Fore.BLUE}-{Style.RESET_ALL}" * 50
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
logging_state = str(settings.get("logging_enabled", "True"))



# Prepare the tools, scanner instance and threading warning
start = False
def main_launching():
    global scanner, enumerator, analyser, profiler
    from tools.scanner import scanner
    from tools.enumerator import enumerator
    from tools.analyser import analyser
    from tools.profiler import profiler
    global scanner_instance
    scanner_instance = scanner.PortScanner()
    print(f"{Style.RESET_ALL}I would like to inform you that there might be some noise in the console when you run the scanner.\n Just be gentle when using ctrl + c on it or ignore it — Python 3.13 threading cleanup is noisy. Not your fault. And neither is mine :3{Fore.BLUE}")
    global start
    start = True

def greating():
    global separators
    print(separators)
    ascii_banner = pyfiglet.figlet_format("INSPECTOR")
    print(f"{Fore.BLUE}{ascii_banner}")
    print(f"Version 0.5.1 BETA{Style.RESET_ALL}")
    print(separators)


def log_creation():
    global output_file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results/INSPECTOR_RESULTS_{timestamp}.txt")
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    output_file = open(output_file_path, "w", encoding="utf-8")
    atexit.register(output_file.close)
    builtins.print = custom_print_true
    banner = pyfiglet.figlet_format("INSPECTOR")
    output_file.write("-" * 50 + "\n")
    output_file.write(banner)
    output_file.write("Version 0.5.0 BETA\n")
    output_file.write("-" * 50 + "\n\n")
    output_file.flush()

def custom_print_true(*args, **kwargs):
    log = kwargs.pop("log", False)
    original_print(*args, **kwargs)
    if log and output_file:
        text = ' '.join(str(arg) for arg in args)
        cleaned = ansi_escape.sub('', text)
        output_file.write(cleaned + '\n')
        output_file.flush()

def custom_print_false(*args, **kwargs):
    kwargs.pop("log", None)
    original_print(*args, **kwargs)

if logging_state == "True":
    builtins.print = custom_print_true
else:
    builtins.print = custom_print_false
def weapon():
    global separators
    greating()
    if not start:
        main_launching()

    print(separators)
    mode = input(f"{Style.RESET_ALL}Pick the tool you wanna use: \n 1. Port Scanner\n 2. Recon & OSINT\n 3. Full Reconnaissance Scan \n 4. Malware Analyser \n ")
    print(separators)

    if mode == "1" or mode.lower() == "port scanner":
        if logging_state == "True":
            log_creation()
        try:
            scanner_instance.scan_port(user_input=input("Enter IP or Domain of the target: "))

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Port Scanner Error: {e}{Style.RESET_ALL}")

    elif mode == "2" or mode.lower() == "recon & osint":
        if logging_state == "True":
            log_creation()
        try:
            print(separators)
            osint_tool = input("Pick your Recon tool \n 1. Subdomain Enumerator \n 2. Directory Brute-Forcer \n 3. DNS Profiler\n")
            print(separators)

            if osint_tool == "1" or osint_tool.lower() == "subdomain enumerator":
                try:
                    enumerator.subdomain_enum(domain_sub=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "2" or osint_tool.lower() == "directory brute-forcer":
                try:
                    enumerator.directory_brute_force(domain_brute=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "3" or osint_tool.lower() == "dns profiler":
                try:
                    print(separators)
                    initializator_profiler = profiler.Profiler(domain=input("Enter domain name: "))
                    initializator_profiler.domain_lookup()
                    initializator_profiler.dns_records_fetching()
                    initializator_profiler.ip_lookup()
                    initializator_profiler.reverse_dns()
                    initializator_profiler.result()
                except Exception as e:
                    print(f"{Fore.RED}[!] Profiler Error: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")



    elif mode == "3" or mode.lower() == "full reconnaissance scan":
        if logging_state == "True":
            log_creation()
        print(separators)
        print(f"{Fore.MAGENTA}This mode will perform full reconnaissance scan on the ip or domain, \nso it will take some time depending on your settings from config.txt{Style.RESET_ALL}")
        proceed = input("Do you want to proceed? (y/n): ")
        if proceed == "y":
            full_scan_ip = input("Enter IP or Domain of the target: ")
            print(f"Proceeding the scan...")
            print(f"\n{separators}\n")
            scanner_instance.scan_port(user_input=full_scan_ip)
            print(f"\n{separators}\n")
            enumerator.subdomain_enum(domain_sub=full_scan_ip)
            print(f"\n{separators}\n")
            enumerator.directory_brute_force(domain_brute=full_scan_ip)
            print(f"\n{separators}\n")
            initializator_profiler = profiler.Profiler(domain=full_scan_ip)
            initializator_profiler.domain_lookup()
            initializator_profiler.dns_records_fetching()
            initializator_profiler.ip_lookup()
            initializator_profiler.reverse_dns()
            initializator_profiler.result()


        elif proceed == "n":
            return
        else:
            print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")


    elif mode == "4" or mode.lower() == "malware analyser":
        if logging_state == "True":
            log_creation()
        try:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Note that Malware analyser uses VirusTotal API. Check the config.txt{Style.RESET_ALL}")
            print(separators)
            analyser.main()
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}") 
        except Exception as e:
            print(f"{Fore.RED}[!] Malware Analyser Error: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")



try:
    while True:
        weapon()
except KeyboardInterrupt:
    print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
