from colorama import Fore, Style
import os
import sys
import json
import re
import platform

def user_settings():
    if platform.system() == "Windows":
        base_dir = os.getenv("APPDATA", os.path.expanduser("~/.config"))
    else:
        base_dir = os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))

    return os.path.join(base_dir, "inspector-cli", "settings.json")

class Guide:
    def __init__(self):
        self.separators = f"{Fore.BLUE}-{Style.RESET_ALL}" * 100

    def port_scanner(self):
        print(f"{Fore.YELLOW}=== Port Scanner ==={Style.RESET_ALL}")
        print("• Scans a target IP or domain for open ports.")
        print("• Supports threading & timeouts (editable in settings.json).")
        print("• Performs banner grabbing on common protocols (HTTP, FTP, SMTP, etc.).")
        print("• Prints open ports with descriptions and possible vulnerabilities.")
        print("• Use when you want to quickly map exposed services on a host.\n")
        print(f"{Fore.BLUE}=== Scanner Settings ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}timeout{Style.RESET_ALL}: Seconds to wait before deciding a port is closed.")
        print("  - Lower = faster, more false negatives")
        print("  - Higher = slower, more accurate")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 0.7s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}max_threads{Style.RESET_ALL}: How many ports scanned at once (parallel workers).")
        print("  - More = faster scans, but too many can crash your PC \n  Edit only when you know what are you doing")
        print(f"  {Fore.LIGHTBLACK_EX}Default: Amount of threads * 75 \n Also worth noting physical cores amount usually does NOT equal to amount of threads{Style.RESET_ALL}")
        print(f"{Fore.CYAN}start_port{Style.RESET_ALL}: First port to scan.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 1{Style.RESET_ALL}")
        print(f"{Fore.CYAN}end_port{Style.RESET_ALL}: Last port to scan.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 1023{Style.RESET_ALL}\n")

    def recon(self):
        print(f"{Fore.YELLOW}=== Recon & OSINT ==={Style.RESET_ALL}")
        print("This menu has 3 tools:")
        print("  1. Subdomain Enumerator")
        print("     - Finds subdomains using a wordlist (set in settings.json).")
        print("     - Detects wildcards and classifies responses (200, 301, 403, etc.).")
        print("  2. Path Enumerator (Directory Brute-Forcer)")
        print("     - Discovers hidden directories on web servers.")
        print("     - Uses a wordlist and classifies responses by status code.")
        print(f"{Fore.BLUE}=== Enumerator Settings ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}semaphore{Style.RESET_ALL}: Max concurrent requests when enumerating.")
        print("  - Prevents flooding your connection")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 10{Style.RESET_ALL}")
        print(f"{Fore.CYAN}timeout{Style.RESET_ALL}: Seconds to wait before marking a subdomain/path as failed.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 3s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}batch_size{Style.RESET_ALL}: How many requests to fire before waiting for results.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 1000{Style.RESET_ALL}")
        print(f"{Fore.CYAN}subdomain_wordlist{Style.RESET_ALL}: Wordlist file used to guess subdomains.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: top_500.txt{Style.RESET_ALL}")
        print(f"{Fore.CYAN}paths_wordlist{Style.RESET_ALL}: Wordlist file used to brute-force directories.")
        print(f"  {Fore.LIGHTBLACK_EX}Default: common_4746.txt{Style.RESET_ALL}\n")
        print("  3. DNS Profiler")
        print("     - Combines WHOIS, DNS records, IP WHOIS, and Reverse DNS.")
        print("     - Gives full context on a domain and its hosting.\n")
        print(f"{Fore.BLUE}DNS Profiler doesn't use setting argumetns.{Style.RESET_ALL}")


    def malware_analyser(self):
        print(f"{Fore.YELLOW}=== Malware Analyser ==={Style.RESET_ALL}")
        print("• Uses VirusTotal API (requires an API key in settings.json).")
        print("• Supports three analysis modes:")
        print("   1. Hash — Identifies hash type (MD5, SHA256, bcrypt, etc.) and queries VT.")
        print("   2. URL — Checks if a URL is malicious, fetches VT report or submits if new.")
        print("   3. File — Uploads a file to VirusTotal for scanning and retrieves the report.")
        print("• Use when you suspect a file, hash, or link is malicious.\n")
        print(f"{Fore.BLUE}=== Malware Analyser Settings ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}vt_api_key{Style.RESET_ALL}: Your VirusTotal API key (needed for hash/URL/file scans).")
        print("  - 'Your_API_key' → not set")
        print("  - Must be 64 hex characters when valid")
        print(f"  {Fore.LIGHTBLACK_EX}Default: 'Your_API_key'{Style.RESET_ALL}")  

    def full_recon(self):
        print(f"{Fore.YELLOW}=== Full Reconnaissance Scan ==={Style.RESET_ALL}")
        print("• Runs Port Scanner + Subdomain Enumeration + Path Enumerator + DNS Profiler in one chain.")
        print("• Best option for a full surface scan on a domain/IP.")
        print("• Takes longer depending on settings and target.\n")

        print(f"{Fore.BLUE}=== General Settings ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}logging_enabled{Style.RESET_ALL}: Whether Inspector-CLI saves results to a log file.")
        print("  - true → scans are saved")
        print("  - false → no logs created")
        print(f"  {Fore.LIGHTBLACK_EX}Default: true{Style.RESET_ALL}\n")




      

class Edit_Settings:
    def __init__(self, settings, settings_path=user_settings()):
        self.settings_path = settings_path
        self.settings = settings

    def current_settings(self):

        print(f"{Fore.BLUE}=== Scanner Settings === {Style.RESET_ALL}")
        scanner = self.settings["scanner"]
        for key, value in scanner.items():
            print(f"{key} - {value}")
        print(f"{Fore.BLUE}=== Enumerator Settings === {Style.RESET_ALL}")
        enumerator = self.settings["enumerator"]
        for key, value in enumerator.items():
            print(f"{key} - {value}")
        print(f"{Fore.BLUE}=== DNS Profiler Settings === {Style.RESET_ALL}")
        scanner = self.settings["scanner"]
        print(f"{Fore.CYAN} DNS Profiler doesnt have settings arguments")
        print(f"{Fore.BLUE}=== Malware Analyzer Settings === {Style.RESET_ALL}")
            
        vt_api_key = self.settings["malware_analyser"]["vt_api_key"]
        vt_api_key = str(vt_api_key)

        if vt_api_key is None:
            print(f"{Fore.YELLOW}VT_api_key = [MISSING from settings.json — add it manually or via Edit Settings]{Style.RESET_ALL}")
        elif vt_api_key.strip() == "Your_API_Key":
            print(f"{Fore.YELLOW}VT_api_key = [NOT SET — please register at virustotal.com]{Style.RESET_ALL}")
        elif re.fullmatch(r"[a-fA-F0-9]{64}", vt_api_key):
            # Mask key for safety
            masked = vt_api_key[:4] + "****" + vt_api_key[-4:]
            print(f"{Fore.GREEN}VT_api_key = {masked} (VALID){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}VT_api_key = [INVALID FORMAT — should be 64 hex characters]{Style.RESET_ALL}")

    def save_settings(self, settings):
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
        with open(self.settings_path, "w") as f:
            json.dump(settings, f, indent=2)

    def edit(self):
        print("Format: <section> <key> <value>")
        print("Example: scanner timeout 1.5")
        print("Type 'exit' or hit ctrl + c to quit.\n")
        try:
            while True:
                raw = input("Edit> ").strip()
                if raw.lower() in ("exit", "quit"):
                    break

                parts = raw.split(maxsplit=2)
                if len(parts) < 3:
                    print("❌ Invalid format. Need <section> <key> <value>")
                    continue

                section, key, value = parts

                if section not in self.settings:
                    print(f"❌ Section '{section}' not found")
                    continue
                if key not in self.settings[section]:
                    print(f"❌ Key '{key}' not found in '{section}'")
                    continue

                # Auto-cast numbers/bools
                if value.isdigit():
                    value = int(value)
                else:
                    try:
                        value = float(value)
                    except ValueError:
                        if value.lower() in ("true", "false"):
                            value = value.lower() == "true"

                self.settings[section][key] = value
                self.save_settings(self.settings)
                print(f"✔ Updated {section}.{key} = {value}")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{Fore.RED} Weird Error occured - {e} {Style.RESET_ALL}")
                



    def intro(self):
        print(f"{Fore.CYAN}=== Inspector-CLI Settings Guide ==={Style.RESET_ALL}\n")

        # General
        print(f"{Fore.YELLOW}General Settings{Style.RESET_ALL}")
        print("  logging_enabled : Enables or disables automatic logging of scan results (True/False).\n")

        # Scanner
        print(f"{Fore.YELLOW}Port Scanner Settings{Style.RESET_ALL}")
        print("  timeout       : How long (in seconds) to wait before considering a port closed.")
        print("  max_threads   : Maximum number of threads to use while scanning.")
        print("  start_port    : The first port number to scan.")
        print("  end_port      : The last port number to scan.\n")

        # Enumerator
        print(f"{Fore.YELLOW}Enumerator Settings{Style.RESET_ALL}")
        print("  semaphore          : Number of concurrent requests allowed at a time.")
        print("  timeout            : Timeout (in seconds) for each request.")
        print("  batch_size         : Number of requests to process before pausing.")
        print("  subdomain_wordlist : Filename of the wordlist for subdomain enumeration.")
        print("  paths_wordlist     : Filename of the wordlist for directory brute-forcing.\n")

        # Malware Analyser
        print(f"{Fore.YELLOW}Malware Analyser Settings{Style.RESET_ALL}")
        print("  vt_api_key : Your VirusTotal API key. Required for hash, URL, and file analysis.\n")
        print(f"{Fore.CYAN}Tip:{Style.RESET_ALL} Edit these values in your JSON settings file to customize Inspector-CLI.")

        

