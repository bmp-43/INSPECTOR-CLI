import builtins
print = builtins.print
import asyncio
import aiohttp
from colorama import Fore, Style
import os
import sys
import contextlib
import signal



def silence_ssl_error(loop, context):
    msg = context.get("exception")
    if msg and "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(msg):
        return  
    loop.default_exception_handler(context)

enumerator_dir = os.path.dirname(os.path.abspath(__file__))


class Subdomain_enumerator:
    def __init__(self, settings, url,
                    success = [],
                    redirect = [],
                    blocked = [],
                    interesting = [],
                    not_found = 0,
                    dns_failures = 0
                ):
        self.settings = settings
        self.url = url
        self.success = success
        self.redirect = redirect
        self.blocked = blocked
        self.interesting = interesting
        self.not_found = not_found
        self.dns_failures = dns_failures

    async def check_wildcards(self, session):
        limit = asyncio.Semaphore(self.settings["enumerator"]["semaphore"])
        wildcards = ["dGhpc3Nob3VsZG5vdGV4aXN0", "d2h5d291bGR5eW91ZGVjb2RldGhpcw==", "SmVzdXNsb3Zlc3lvdQ=="] 
        async with limit:
            try:
                false_positives = 0
                for wildcard in wildcards:
                    url = f"https://{wildcard}.{self.url}"
                    async with session.get(url, timeout=float(self.settings["enumerator"]["timeout"])) as resp:
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
                print(f"{Fore.CYAN}[i] Did you mess with settings file?{Style.RESET_ALL}")

    async def fetch(self, url, session):
        try:
            async with session.get(url, timeout=float(self.settings["enumerator"]["timeout"])) as resp:
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
            print(f"{Fore.CYAN}[i] Did you mess with settings file?{Style.RESET_ALL}")
        except ConnectionResetError:
            print(f"{Fore.YELLOW}[x] Connection reset by peer{Style.RESET_ALL}")

    async def main(self):
        wordlist_path = "subdomains/" + self.settings["enumerator"]["subdomain_wordlist"]
        if not wordlist_path:
            print(f"{Fore.RED}[!] No wordlist path set in settings!{Style.RESET_ALL}")
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
                batch_size = int(self.settings["enumerator"]["batch_size"])
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
    def __init__(self, settings, url,
                success = [],
                redirect = [],
                blocked = [],
                interesting = [],
                not_found = 0,
                dns_failures = 0):
        self.settings = settings
        self.url = url
        self.success = success
        self.redirect = redirect
        self.blocked = blocked
        self.interesting = interesting
        self.not_found = not_found
        self.dns_failures = dns_failures

    async def fetch(self, url, session):
        fake_path = "/c655f7fb29b00ed5021718ac7ee444b72e56e7547e3afc407c839f72f8f92f8e"
        try:
            async with session.get(url + fake_path, timeout=float(self.settings["enumerator"]["timeout"])) as baseline_resp:
                baseline_html = await baseline_resp.text()
                async with session.get(url, timeout=float(self.settings["enumerator"]["timeout"])) as resp:
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
            print(f"{Fore.CYAN}[i] Did you mess with settings file?{Style.RESET_ALL}")
        except ConnectionResetError:
            print(f"{Fore.YELLOW}[x] Connection reset by peer{Style.RESET_ALL}")

    async def main(self):
        wordlist_path = "paths/" + self.settings["enumerator"]["paths_wordlist"]
        if not wordlist_path:
            print(f"{Fore.RED}[!] No wordlist path set in settings!{Style.RESET_ALL}")
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
                batch_size = int(self.settings["enumerator"]["batch_size"])
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
    asyncio.set_event_loop(loop)
    loop.set_exception_handler(lambda *a: None)

    ctrl_c_counter = [0]

    def block_ctrl_c(sig, frame):
        ctrl_c_counter[0] += 1
        if ctrl_c_counter[0] == 1:
            print(f"{Fore.YELLOW}[x] Shutting down... please wait.{Style.RESET_ALL}")
        elif ctrl_c_counter[0] == 2:
            print(f"{Fore.RED}[!] Forcing shutdown. Cleaning may be incomplete.{Style.RESET_ALL}")
        else:
            print(f"{Fore.LIGHTRED_EX}[x] Killing everything. Expect garbage.{Style.RESET_ALL}")
            os._exit(1)

    signal.signal(signal.SIGINT, block_ctrl_c)

    try:
        loop.run_until_complete(coro)
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Cleaning up...{Style.RESET_ALL}")
    finally:
        with contextlib.suppress(asyncio.CancelledError, Exception):
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        with contextlib.suppress(Exception):
            loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()




def subdomain_enum(settings, domain_sub):
    print("-" * 50)
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Using subdomain wordlist from settings: {settings['enumerator']['subdomain_wordlist']}")
    print(f"{Fore.LIGHTBLACK_EX}Edit settings to change the wordlist path.{Style.RESET_ALL}")
    print("-" * 50)
    try:
        if domain_sub.startswith("http://"):
            domain_sub = domain_sub[7:]
        elif domain_sub.startswith("https://"):
            domain_sub = domain_sub[8:]
        subdomain_enumerator_instance = Subdomain_enumerator(settings, url=domain_sub)  
        run_with_handler(subdomain_enumerator_instance.main())   
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")

def directory_brute_force(settings, domain_brute):
    print("-" * 50)
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Using path wordlist from settings: {settings['enumerator']['paths_wordlist']}")
    print(f"{Fore.LIGHTBLACK_EX}Edit settings to change the wordlist path.{Style.RESET_ALL}")
    print("-" * 50)
    try:
        if domain_brute.startswith("http://"):
            domain_brute = domain_brute[7:]
        elif domain_brute.startswith("https://"):
            domain_brute = domain_brute[8:]
        path_enumerator_instance = Path_enumerator(settings, url=domain_brute)  
        run_with_handler(path_enumerator_instance.main())   
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[x] Interrupted by user. Shutting down...{Style.RESET_ALL}")


