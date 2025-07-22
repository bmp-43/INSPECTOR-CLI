import builtins
print = builtins.print
import asyncio
import aiohttp
from colorama import Fore, Style
import os
import sys

def config(filename):
    config = {}
    with open(filename, "r") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value
    return config

base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
enumerator_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(base_dir, "config", "config.txt")
if not os.path.isfile(config_path):
    print(f"{Fore.RED}[!] Config file not found at: {config_path}{Style.RESET_ALL}")
    sys.exit(1)

settings = config(config_path)

def silence_ssl_error(loop, context):
    msg = context.get("exception")
    if msg and "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(msg):
        return  
    loop.default_exception_handler(context)

limit = asyncio.Semaphore(float(settings.get("semaphore", 10))) 

class Subdomain_enumerator:
    def __init__(self, url,
                    success = [],
                    redirect = [],
                    blocked = [],
                    interesting = [],
                    not_found = 0,
                    dns_failures = 0
                ):
        self.url = url
        self.success = success
        self.redirect = redirect
        self.blocked = blocked
        self.interesting = interesting
        self.not_found = not_found
        self.dns_failures = dns_failures

    async def check_wildcards(self, session):
        wildcards = ["dGhpc3Nob3VsZG5vdGV4aXN0", "d2h5d291bGR5eW91ZGVjb2RldGhpcw==", "SmVzdXNsb3Zlc3lvdQ=="] 
        async with limit:
            try:
                false_positives = 0
                for wildcard in wildcards:
                    url = f"https://{wildcard}.{self.url}"
                    async with session.get(url, timeout=float(settings.get("timeout_enumerator", 5))) as resp:
                        status = resp.status
                        if status != 404:
                            false_positives += 1

                if false_positives == 3:
                    print(f"{Fore.RED}[!] {self.url} uses DNS wildcards protection. Subdomain enumeration is pointless :({Style.RESET_ALL}", log=True)
                    sys.exit()
                else:
                    print(f"{Fore.GREEN}Service has no wildcard block! Proceeding enumeration...{Style.RESET_ALL}", log=True)
            except aiohttp.client_exceptions.ClientConnectorDNSError:
                print(f"{Fore.GREEN}Service has no wildcard block! Proceeding enumeration...{Style.RESET_ALL}", log=True)
            except aiohttp.client_exceptions.ClientConnectionError:
                pass
            except TimeoutError:
                print(f"{Fore.CYAN}[i] Did you mess with config file?{Style.RESET_ALL}")

    async def fetch(self, url, session):
        try:
            async with session.get(url, timeout=float(settings.get("timeout_enumerator", 5))) as resp:
                status = resp.status

                if status == 200:
                    print(f"{Fore.GREEN}[200] ACTIVE — Subdomain responded successfully: {url}{Style.RESET_ALL}", log=True)
                    self.success.append(url)
                elif status == 301 or status == 302:
                    print(f"{Fore.CYAN}[{status}] REDIRECT — Subdomain is alive but redirects: {url}{Style.RESET_ALL}", log=True)
                    self.redirect.append(url)
                elif status == 401:
                    print(f"{Fore.YELLOW}[401] AUTH REQUIRED — Subdomain is protected by login: {url}{Style.RESET_ALL}", log=True)
                    self.blocked.append(url)
                elif status == 403:
                    print(f"{Fore.YELLOW}[403] FORBIDDEN — Access to subdomain is blocked: {url}{Style.RESET_ALL}", log=True)
                    self.blocked.append(url)
                elif status == 405:
                    print(f"{Fore.MAGENTA}[405] METHOD BLOCKED — Subdomain rejects GET requests, somethings there!: {url}{Style.RESET_ALL}", log=True)
                    self.interesting.append(url)
                elif status == 404:
                    self.not_found += 1
                else:
                    print(f"{Fore.MAGENTA}[{status}] UNKNOWN — Unexpected response from subdomain: {url}{Style.RESET_ALL}", log=True)
                    self.interesting.append(url)
        except aiohttp.ClientConnectorError:
            self.dns_failures += 1
        except asyncio.TimeoutError:
            self.dns_failures += 1
        except Exception as e:
            print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")
            self.dns_failures += 1
        except TimeoutError:
            print(f"{Fore.CYAN}[i] Did you mess with config file?{Style.RESET_ALL}")
        except ConnectionResetError:
            print(f"{Fore.YELLOW}[x] Connection reset by peer{Style.RESET_ALL}")

    async def main(self):
        wordlist_path = "subdomains/" + str(settings.get('subdomain_wordlist'))
        if not wordlist_path:
            print(f"{Fore.RED}[!] No wordlist path set in config!{Style.RESET_ALL}")
            return
        if not os.path.isabs(wordlist_path):
            wordlist_path = os.path.join(enumerator_dir, wordlist_path)
        if not os.path.isfile(wordlist_path):
            print(f"{Fore.RED}[!] Wordlist file not found: {wordlist_path}{Style.RESET_ALL}")
            return

        connector = aiohttp.TCPConnector(limit=100, force_close=True)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                await self.check_wildcards(session)
                batch = []
                batch_size = int(settings.get("batch", 1000))
                with open(wordlist_path, "r") as f:
                    for line in f:
                        subdomain = line.strip()
                        if not subdomain:
                            continue
                        url = f"https://{subdomain}.{self.url}"
                        batch.append(self.fetch(url, session))
                        if len(batch) >= batch_size:
                            await asyncio.gather(*batch)
                            batch = []
                    if batch:
                        await asyncio.gather(*batch)

                print("\n--- SUMMARY ---", log=True)
                print(f"{Fore.GREEN}{len(self.success)} Active subdomains found{Style.RESET_ALL}", log=True)
                print(f"{Fore.CYAN}{len(self.redirect)} Redirects{Style.RESET_ALL}", log=True)
                print(f"{Fore.YELLOW}{len(self.blocked)} Blocked (401/403){Style.RESET_ALL}", log=True)
                print(f"{Fore.MAGENTA}{len(self.interesting)} Interesting (405/other){Style.RESET_ALL}", log=True)
                print(f"{Fore.RED}{self.not_found} Not found (404){Style.RESET_ALL}", log=True)
                print(f"{Fore.LIGHTBLACK_EX}{self.dns_failures} DNS/Timeout failures{Style.RESET_ALL}", log=True)
            except Exception as e:
                print(f"{Fore.RED}[!] Subdomain Enumerator Error: {e}{Style.RESET_ALL}")

class Path_enumerator:
    def __init__(self, url,
                success = [],
                redirect = [],
                blocked = [],
                interesting = [],
                not_found = 0,
                dns_failures = 0):
        self.url = url
        self.success = success
        self.redirect = redirect
        self.blocked = blocked
        self.interesting = interesting
        self.not_found = not_found
        self.dns_failures = dns_failures

    async def fetch(self, url, session):
        fake_path = "/theresnochancethispathexists321123"
        try:
            async with session.get(url + fake_path, timeout=float(settings.get("timeout_enumerator", 5))) as baseline_resp:
                baseline_html = await baseline_resp.text()

            async with session.get(url, timeout=float(settings.get("timeout_enumerator", 5))) as resp:
                status = resp.status

                if status == 200:
                    if any(keyword in baseline_html.lower() for keyword in ["404", "not found", "does not exist"]):
                        self.not_found += 1
                    else:
                        print(f"{Fore.GREEN}[200] ACTIVE — Path responded successfully: {url}{Style.RESET_ALL}", log=True)
                        self.success.append(url)
                elif status == 301 or status == 302:
                    print(f"{Fore.CYAN}[{status}] REDIRECT — Path is alive but redirects: {url}{Style.RESET_ALL}", log=True)
                    self.redirect.append(url)
                elif status == 401:
                    print(f"{Fore.YELLOW}[401] AUTH REQUIRED — Path is protected by login: {url}{Style.RESET_ALL}", log=True)
                    self.blocked.append(url)
                elif status == 403:
                    print(f"{Fore.YELLOW}[403] FORBIDDEN — Access to path is blocked: {url}{Style.RESET_ALL}", log=True)
                    self.blocked.append(url)
                elif status == 405:
                    print(f"{Fore.MAGENTA}[405] METHOD BLOCKED — Path rejects GET requests, somethings there!: {url}{Style.RESET_ALL}", log=True)
                    self.interesting.append(url)
                elif status == 404:
                    self.not_found += 1
                else:
                    print(f"{Fore.MAGENTA}[{status}] UNKNOWN — Unexpected response from chosen path: {url}{Style.RESET_ALL}", log=True)
                    self.interesting.append(url)
        except aiohttp.ClientConnectorError:
            self.dns_failures += 1
        except asyncio.TimeoutError:
            self.dns_failures += 1
        except Exception as e:
            print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")
            self.dns_failures += 1
        except TimeoutError:
            print(f"{Fore.CYAN}[i] Did you mess with config file?{Style.RESET_ALL}")
        except ConnectionResetError:
            print(f"{Fore.YELLOW}[x] Connection reset by peer{Style.RESET_ALL}")

    async def main(self):
        wordlist_path = "paths/" + str(settings.get('paths_wordlist'))
        if not wordlist_path:
            print(f"{Fore.RED}[!] No wordlist path set in config!{Style.RESET_ALL}")
            return
        if not os.path.isabs(wordlist_path):
            wordlist_path = os.path.join(enumerator_dir, wordlist_path)
        if not os.path.isfile(wordlist_path):
            print(f"{Fore.RED}[!] Wordlist file not found: {wordlist_path}{Style.RESET_ALL}")
            return

        connector = aiohttp.TCPConnector(limit=100, force_close=True)

        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                batch = []
                batch_size = int(settings.get("batch", 1000))
                with open(wordlist_path, "r") as f:
                    for line in f:
                        path = line.strip()
                        if not path:
                            continue
                        url = f"https://{self.url}/{path}"
                        batch.append(self.fetch(url, session))
                        if len(batch) >= batch_size:
                            await asyncio.gather(*batch)
                            batch = []
                    if batch:
                        await asyncio.gather(*batch)

                print("\n--- SUMMARY ---", log=True)
                print(f"{Fore.GREEN}{len(self.success)} Active paths found{Style.RESET_ALL}", log=True)
                print(f"{Fore.CYAN}{len(self.redirect)} Redirects{Style.RESET_ALL}", log=True)
                print(f"{Fore.YELLOW}{len(self.blocked)} Blocked (401/403){Style.RESET_ALL}", log=True)
                print(f"{Fore.MAGENTA}{len(self.interesting)} Interesting (405/other){Style.RESET_ALL}", log=True)
                print(f"{Fore.RED}{self.not_found} Not found (404){Style.RESET_ALL}", log=True)
                print(f"{Fore.LIGHTBLACK_EX}{self.dns_failures} DNS/Timeout failures{Style.RESET_ALL}", log=True)
            except Exception as e:
                print(f"{Fore.RED}[!] Path Enumerator Error: {e}{Style.RESET_ALL}")

def run_with_handler(coro):
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(silence_ssl_error)
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(coro)
    finally:
        loop.close()

def subdomain_enum():
    global domain
    print("-" * 50)
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Using subdomain wordlist from config: {settings.get('subdomain_wordlist')}")
    print(f"{Fore.LIGHTBLACK_EX}Edit 'config.txt' to change the wordlist path.{Style.RESET_ALL}")
    print("-" * 50)
    try:
        domain = input("Enter the root domain (e.g google.com): ").strip().lower()
        if domain.startswith("http://"):
            domain = domain[7:]
        elif domain.startswith("https://"):
            domain = domain[8:]
        subdomain_enumerator_instance = Subdomain_enumerator(url=domain)  
        run_with_handler(subdomain_enumerator_instance.main())   
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")

def directory_brute_force():
    print("-" * 50)
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Using path wordlist from config: {settings.get('paths_wordlist')}")
    print(f"{Fore.LIGHTBLACK_EX}Edit 'config.txt' to change the wordlist path.{Style.RESET_ALL}")
    print("-" * 50)
    try:
        domain = input("Enter the root domain (e.g google.com): ").strip().lower()
        if domain.startswith("http://"):
            domain = domain[7:]
        elif domain.startswith("https://"):
            domain = domain[8:]
        path_enumerator_instance = Path_enumerator(url=domain)  
        run_with_handler(path_enumerator_instance.main())   
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        mode = (input("Pick your mode\n 1. Subdomain enumerator\n 2. Directory Brute-Forcer \n "))
        if mode.strip() == "1":
            subdomain_enum()
        elif mode.strip() == "2":
            directory_brute_force()
        else:
            print(f"{Fore.YELLOW}[?] Invalid mode selected.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")
