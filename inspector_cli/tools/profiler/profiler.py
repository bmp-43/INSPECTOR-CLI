import builtins
print = builtins.print
import whois
from colorama import Fore, Style
import dns.resolver
import socket
from ipwhois import IPWhois

class Profiler:
    def __init__(self, settings, domain):
        self.settings = settings
        self.domain = domain
        self.domain_info = {}
        self.dates = {}
        self.name_servers = []
        self.contact = {}
        self.security = None
        self.additional_info = {}
        self.record_types = {
            "A":     "Maps domain to IPv4 address",
            "AAAA":  "Maps domain to IPv6 address",
            "MX":    "Mail servers responsible for email",
            "TXT":   "Text records (SPF, verification, etc.)",
            "NS":    "Authoritative name servers for the domain",
            "CNAME": "Alias pointing to another domain",
            "SOA":   "Start of Authority — DNS admin & config"
        }
        self.results = {}
        self.ipv4 = ""
        self.ipv6 = ""
        self.reversed_dns = []
        self.ip_whois = {}

    def domain_lookup(self):
        try:
            response = whois.whois(self.domain)
            self.domain_info = {
                "domain": response.get("domain_name"),
                "registrar": response.get("registrar"),
                "registrar_url": response.get("registrar_url"),
                "whois_server": response.get("whois_server"),
            }
            self.dates = {
                "created": response.get("creation_date")[-1] if isinstance(response.get("creation_date"), list) else response.get("creation_date"),
                "updated": response.get("updated_date")[-1] if isinstance(response.get("updated_date"), list) else response.get("updated_date"),
                "expires": response.get("expiration_date")[-1] if isinstance(response.get("expiration_date"), list) else response.get("expiration_date"),
            }
            self.name_servers = response.get("name_servers", [])
            self.contact = {
                "emails": response.get("emails", []),
                "phone": response.get("phone")
            }
            self.security = response.get("dnssec")
            self.additional_info = {
                "status": response.get("status", []),
                "reseller": response.get("reseller"),
                "referral_url": response.get("referral_url"),
                "name": response.get("name"),
                "address": response.get("address"),
                "city": response.get("city"),
                "state": response.get("state"),
                "registrant_postal_code": response.get("registrant_postal_code")
            }
        except Exception as e:
            print(f"{Fore.RED}[!] WHOIS lookup failed: {e}{Style.RESET_ALL}")

    def ip_lookup(self):
        try:
            for ip in self.ipv4 + self.ipv6:
                try:
                    obj = IPWhois(ip)
                    res = obj.lookup_rdap()
                    self.ip_whois[ip] = {
                        "name": res["network"]["name"],
                        "cidr": res["network"]["cidr"],
                        "asn": res.get("asn_description"),
                        "country": res["network"]["country"]
                    }
                except Exception:
                    self.ip_whois[ip] = None
        except Exception as e:
            print(f"{Fore.RED}[!] IP WHOIS lookup error: {e}{Style.RESET_ALL}")

    def dns_records_fetching(self):
        try:
            for rtype in self.record_types:
                try:
                    answers = dns.resolver.resolve(self.domain, rtype)
                    records = []
                    for record in answers:
                        records.append(record.to_text())
                    self.results[rtype] = records
                except Exception:
                    self.results[rtype] = []
            self.ipv4 = self.results.get("A", [])
            self.ipv6 = self.results.get("AAAA", [])
        except Exception as e:
            print(f"{Fore.RED}[!] DNS records fetch error: {e}{Style.RESET_ALL}")

    def reverse_dns(self):
        try:
            for ip in self.ipv4 + self.ipv6:
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    self.reversed_dns.append((ip, hostname))
                except Exception:
                    self.reversed_dns.append((ip, None))
        except Exception as e:
            print(f"{Fore.RED}[!] Reverse DNS lookup error: {e}{Style.RESET_ALL}")

    def result(self):
        try:
            print(f"\n{Fore.LIGHTCYAN_EX}=== Domain WHOIS information ==={Style.RESET_ALL}", log=True)
            print(f"{Fore.BLUE}Domain Information{Style.RESET_ALL}", log=True)
            for i in self.domain_info:
                if self.domain_info[i]:
                    print(f"  {i.capitalize()}: {self.domain_info[i]}", log=True)

            print(f"\n{Fore.YELLOW}Dates{Style.RESET_ALL}", log=True)
            for i in self.dates:
                if self.dates[i]:
                    print(f"  {i.capitalize()}: {self.dates[i]}", log=True)

            if self.name_servers:
                print(f"\n{Fore.GREEN}Name Servers{Style.RESET_ALL}", log=True)
                for ns in self.name_servers:
                    print(f"  - {ns}", log=True)

            print(f"\n{Fore.GREEN}Contact Info{Style.RESET_ALL}", log=True)
            for i in self.contact:
                if self.contact[i]:
                    if isinstance(self.contact[i], list):
                        for item in self.contact[i]:
                            print(f"  {i.capitalize()}: {item}", log=True)
                    else:
                        print(f"  {i.capitalize()}: {self.contact[i]}", log=True)

            if self.security:
                print(f"\n{Fore.RED}DNS Security{Style.RESET_ALL}", log=True)
                print(f"  DNSSEC: {self.security}", log=True)

            filtered = {i: self.additional_info[i] for i in self.additional_info if self.additional_info[i]}
            if filtered:
                print(f"\n{Fore.LIGHTBLACK_EX}Additional Info{Style.RESET_ALL}", log=True)
                for i in filtered:
                    if isinstance(filtered[i], list):
                        for item in filtered[i]:
                            print(f"  {i.capitalize()}: {item}", log=True)
                    else:
                        print(f"  {i.capitalize()}: {filtered[i]}", log=True)

            print(f"\n{Fore.CYAN}=== IP WHOIS Information ==={Style.RESET_ALL}", log=True)
            for ip, info in self.ip_whois.items():
                print(f"\n  {ip}:", log=True)
                if info:
                    for key, value in info.items():
                        print(f"    {key.capitalize()}: {value}", log=True)
                else:
                    print("    No WHOIS data found.", log=True)

            print(f"\n{Fore.LIGHTCYAN_EX}=== Resolved DNS Information ==={Style.RESET_ALL}", log=True)
            for rtype, info in self.results.items():
                description = self.record_types.get(rtype, "")
                if info:
                    print(f"{Fore.YELLOW} \n{rtype} Records: - {description}{Style.RESET_ALL}", log=True)
                    for r in info:
                        print(f" - {r}", log=True)

            print(f"\n{Fore.LIGHTCYAN_EX}=== Reversed DNS information ==={Style.RESET_ALL}", log=True)
            for ip, host in self.reversed_dns:
                if host:
                    print(f"  {ip} → {host}", log=True)
                else:
                    print(f"  {ip} → No reverse DNS found", log=True)

        except Exception as e:
            print(f"{Fore.RED}[!] Error printing results: {e}{Style.RESET_ALL}")


