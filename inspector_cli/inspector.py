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
import json
import platform
from time import sleep


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
max_threads = os.cpu_count() * 75


DEFAULT_SETTINGS = {
    "logging_enabled": True,
    "scanner": {
        "timeout": 0.7,
        "max_threads": max_threads,
        "start_port": 1,
        "end_port": 1023
    },
    "enumerator": {
        "semaphore": 10,
        "timeout": 3,
        "batch_size": 1000,
        "subdomain_wordlist": "top_500.txt",
        "paths_wordlist": "common_4746.txt"
    },
    "malware_analyser": {
        "vt_api_key": "Your_API_Key"
    }
}

def user_settings():
    if platform.system() == "Windows":
        base_dir = os.getenv("APPDATA", os.path.expanduser("~/.config"))
    else:
        base_dir = os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))

    return os.path.join(base_dir, "inspector-cli", "settings.json")




def load_settings():
    path = user_settings()

    # If settings.json doesn’t exist → create with defaults
    if not os.path.isfile(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)
        print(f"{Fore.YELLOW}[i] Default settings created at {path}{Style.RESET_ALL}")
        return DEFAULT_SETTINGS.copy()

    # If it exists → try loading
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        print(f"{Fore.RED}[!] Error reading settings.json. Resetting to defaults.{Style.RESET_ALL}")
        return DEFAULT_SETTINGS.copy()




settings = load_settings()

logging_state = settings["logging_enabled"]



# Prepare the tools, scanner instance and threading warning
start = False
def main_launching():
    global scanner, enumerator, analyser, profiler, guide_settings
# cli.py
    from tools.scanner import scanner
    from tools.enumerator import enumerator
    from tools.analyser import analyser
    from tools.profiler import profiler
    from config import guide_settings
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

if logging_state:
    builtins.print = custom_print_true
else:
    builtins.print = custom_print_false
def weapon():
    global separators
    greating()
    if not start:
        main_launching()

    print(separators)
    mode = input(f"{Style.RESET_ALL}Pick the tool you wanna use: \n 1. Port Scanner\n 2. Recon & OSINT\n 3. Full Reconnaissance Scan \n 4. Malware Analyser \n 5. Guide & Settings \n")
    print(separators)

    if mode == "1" or mode.lower() == "port scanner":
        if logging_state:
            log_creation()
        try:
            scanner_instance.scan_port(user_input=input("Enter IP or Domain of the target: "))

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Port Scanner Error: {e}{Style.RESET_ALL}")

    elif mode == "2" or mode.lower() == "recon & osint":
        if logging_state:
            log_creation()
        try:
            print(separators)
            osint_tool = input("Pick your Recon tool \n 1. Subdomain Enumerator \n 2. Directory Brute-Forcer \n 3. DNS Profiler\n")
            print(separators)

            if osint_tool == "1" or osint_tool.lower() == "subdomain enumerator":
                try:
                    enumerator.subdomain_enum(settings=settings, domain_sub=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "2" or osint_tool.lower() == "directory brute-forcer":
                try:
                    enumerator.directory_brute_force(settings=settings, domain_brute=input("Enter the root domain (e.g google.com): ").strip().lower())
                except Exception as e:
                    print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")

            elif osint_tool == "3" or osint_tool.lower() == "dns profiler":
                try:
                    print(separators)
                    initializator_profiler = profiler.Profiler(settings=settings, domain=input("Enter domain name: "))
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
        if logging_state:
            log_creation()
        print(separators)
        print(f"{Fore.MAGENTA}This mode will perform full reconnaissance scan on the ip or domain, \nso it will take some time depending on your settings from settings.json{Style.RESET_ALL}")
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
        if logging_state:
            log_creation()
        try:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Note that Malware analyser uses VirusTotal API. Check the settings.json{Style.RESET_ALL}")
            print(separators)
            try:
                if not analyser.check_vt_key_valid(api_key=settings["malware_analyser"]["vt_api_key"]):
                    print(f"{Fore.RED}[!] Invalid VirusTotal API key. Please check your settings{Style.RESET_ALL}", log=True)
                    sys.exit()
            except Exception as e:
                print(f"{Fore.RED}[!] Unexpected error occurred. - {e}{Style.RESET_ALL}", log=True)


            try:
                mode = input("Pick What are you gonna Analyse: \n 1. Hash \n 2. URL \n 3. File \n")
                if mode == "1" or mode.lower() == "hash":
                    hash_instance = analyser.HashScanner(settings=settings, api_key=settings["malware_analyser"]["vt_api_key"], h_value=input("Provide hash for scanning: ").strip())
                    hash_instance.start()
                elif mode == "2" or mode.lower() == "url":
                    url_instance = analyser.UrlAnalyser(settings=settings, api_key=settings["malware_analyser"]["vt_api_key"], url=input("Provide URL for scanning: ").strip())
                    url_instance.vt_url_lookup()
                elif mode == "3" or mode.lower() == "file":
                    file_instance = analyser.FileAnalyser(settings=settings, api_key=settings["malware_analyser"]["vt_api_key"], file_path=input("Enter path to file: ").strip())
                    file_instance.vt_file_scan()

            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}", log=True)
            except Exception as e:
                print(f"{Fore.RED}[!] Unexpected error occurred. - {e}{Style.RESET_ALL}", log=True)

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}") 
        except Exception as e:
            print(f"{Fore.RED}[!] Malware Analyser Error: {e}{Style.RESET_ALL}")
    
    elif mode == "5" or mode.lower() == "guide" or mode.lower() == "settings":
        print(f"{Fore.BLUE}Would you like to view the Inspector-CLI guide or edit the settings file?{Style.RESET_ALL}")
        guide_init = guide_settings.Guide()
        settings_init = guide_settings.Edit_Settings(settings=load_settings())
        option = input("Enter 1. Guide 2. View Current Settings 3. Edit Settings\n")
        if option == "1" or option.lower() == "guide":
            guide_init.port_scanner()
            guide_init.recon()
            guide_init.malware_analyser()
            guide_init.full_recon()
        elif option == "2" or option.lower() == "view current settings":
            settings_init.current_settings()
        elif option == "3" or option.lower() == "edit settings":
            settings_init.edit()
            



    else:
        print(f"{Fore.YELLOW}[?] Invalid option selected.{Style.RESET_ALL}")

try:
    load_settings()
    while True:
        weapon()
        sleep(2)
        
except KeyboardInterrupt:
    print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
    sys.exit()
