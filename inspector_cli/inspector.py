import builtins
import os
import atexit
import re
from datetime import datetime
import pyfiglet
from colorama import Fore, Style
import sys
import shutil
from importlib.metadata import version, PackageNotFoundError

def print_version():
    try:
        v = version("inspector-cli")
        print(f"Inspector CLI v{v}")
    except PackageNotFoundError:
        print("Inspector CLI (version unknown — not installed)")

if "--version" in sys.argv:
    print_version()
    sys.exit()

original_print = builtins.print
output_file = None
ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
separators = f"{Fore.BLUE}-{Style.RESET_ALL}" * 100

base_dir = os.path.dirname(os.path.abspath(__file__))

# Setup default and user config paths
def get_user_config_path():
    user_config = os.path.expanduser("~/.config/inspector-cli/config.txt")
    default_config = os.path.join(base_dir, "config", "config.txt")

    # Copy default if user config doesn't exist
    if not os.path.isfile(user_config):
        os.makedirs(os.path.dirname(user_config), exist_ok=True)
        shutil.copy(default_config, user_config)
        print(f"{Fore.YELLOW}[i] Default config copied to: {user_config}{Style.RESET_ALL}")
    else:
        # Check for missing keys and auto-patch
        with open(default_config, "r") as f:
            default_lines = [line.strip() for line in f if "=" in line]
            default_keys = {line.split("=", 1)[0] for line in default_lines}

        with open(user_config, "r") as f:
            user_lines = [line.strip() for line in f if "=" in line]
            user_keys = {line.split("=", 1)[0] for line in user_lines}

        missing_keys = default_keys - user_keys

        if missing_keys:
            print(f"{Fore.CYAN}[i] Updating config with missing keys: {', '.join(missing_keys)}{Style.RESET_ALL}")
            with open(default_config, "r") as f:
                default_config_dict = {
                    line.split("=", 1)[0]: line for line in f if "=" in line
                }

            with open(user_config, "a") as f:
                for key in missing_keys:
                    f.write(default_config_dict[key] + "\n")

    return user_config


# Load config from user directory
final_config_path = get_user_config_path()

def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

settings = config(final_config_path)

logging_state = str(settings.get("logging_enabled", "True"))



# Prepare the tools, scanner instance and threading warning
start = False
def main_launching():
    global scanner, enumerator, analyser, profiler
# cli.py
    from inspector_cli.tools.scanner import scanner
    from inspector_cli.tools.enumerator import enumerator
    from inspector_cli.tools.analyser import analyser
    from inspector_cli.tools.profiler import profiler
    global scanner_instance
    scanner_instance = scanner.PortScanner(settings)
    global start
    start = True

version = "Version 1.0.0"

def greating():
    global separators
    print(separators)
    ascii_banner = pyfiglet.figlet_format("INSPECTOR - CLI")
    print(f"{Fore.BLUE}{ascii_banner}")
    print(f"{version}")
    print(f"Developed by Aegis Martin — https://aegismartin.com{Style.RESET_ALL}")

def log_creation():
    global output_file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results/INSPECTOR_RESULTS_{timestamp}.txt")
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    output_file = open(output_file_path, "w", encoding="utf-8")
    atexit.register(output_file.close)
    builtins.print = custom_print_true
    banner = pyfiglet.figlet_format("INSPECTOR")
    output_file.write("-" * 100 + "\n")
    output_file.write(banner)
    output_file.write(f"{version} \n")
    output_file.write("-" * 100 + "\n\n")
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
                    enumerator.subdomain_enum(settings, domain_sub=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "2" or osint_tool.lower() == "directory brute-forcer":
                try:
                    enumerator.directory_brute_force(settings, domain_brute=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "3" or osint_tool.lower() == "dns profiler":
                try:
                    print(separators)
                    initializator_profiler = profiler.Profiler(settings, domain=input("Enter domain name: "))
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
            enumerator.subdomain_enum(settings, domain_sub=full_scan_ip)
            print(f"\n{separators}\n")
            enumerator.directory_brute_force(settings, domain_brute=full_scan_ip)
            print(f"\n{separators}\n")
            initializator_profiler = profiler.Profiler(settings, domain=full_scan_ip)
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
            analyser.main(settings)
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
    sys.exit()
