import whois
from colorama import Fore, Style
import dns.resolver
class Profiler:
    def __init__(self, domain):
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

    def lookup(self):
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

    
    def dns_records_fetching(self):
        

        for rtype in self.record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = []
                for record in answers:
                    records.append(record.to_text())
                self.results[rtype] = records

            except Exception:
                self.results[rtype] = []





    def result(self):

        #Whois result

        print(f"{Fore.BLUE}Domain Information{Style.RESET_ALL}")
        for i in self.domain_info:
            if self.domain_info[i]:
                print(f"  {i.capitalize()}: {self.domain_info[i]}")

        print(f"\n{Fore.YELLOW}Dates{Style.RESET_ALL}")
        for i in self.dates:
            if self.dates[i]:
                print(f"  {i.capitalize()}: {self.dates[i]}")

        if self.name_servers:
            print(f"\n{Fore.GREEN}Name Servers{Style.RESET_ALL}")
            for ns in self.name_servers:
                print(f"  - {ns}")

        print(f"\n{Fore.CYAN}Contact Info{Style.RESET_ALL}")
        for i in self.contact:
            if self.contact[i]:
                if isinstance(self.contact[i], list):
                    for item in self.contact[i]:
                        print(f"  {i.capitalize()}: {item}")
                else:
                    print(f"  {i.capitalize()}: {self.contact[i]}")

        if self.security:
            print(f"\n{Fore.RED}DNS Security{Style.RESET_ALL}")
            print(f"  DNSSEC: {self.security}")

        filtered = {i: self.additional_info[i] for i in self.additional_info if self.additional_info[i]}
        if filtered:
            print(f"\n{Fore.LIGHTBLACK_EX}Additional Info{Style.RESET_ALL}")
            for i in filtered:
                if isinstance(filtered[i], list):
                    for item in filtered[i]:
                        print(f"  {i.capitalize()}: {item}")
                else:
                    print(f"  {i.capitalize()}: {filtered[i]}")


        #Resolved DNS
        print(f"\n{Fore.LIGHTCYAN_EX}=== Resolved DNS Information ==={Style.RESET_ALL}")
        for rtype, info in self.results.items():
            description = self.record_types.get(rtype, "")
            if info:
                print(f"{Fore.YELLOW} \n{rtype} Records: - {description}{Style.RESET_ALL}")
                for r in info:
                    print(f" - {r}")


      


if __name__ == "__main__":
    initializator=Profiler(domain=input("Enter domain name: "))
    initializator.lookup()
    initializator.dns_records_fetching()
    initializator.result()

