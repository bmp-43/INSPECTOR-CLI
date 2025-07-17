import whois
from colorama import Fore, Style
class Profiler:
    def __init__(self, domain):
        self.domain = domain
        self.domain_info = {}
        self.dates = {}
        self.name_servers = []
        self.contact = {}
        self.security = None
        self.additional_info = {}


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

    
    def result(self):
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





if __name__ == "__main__":
    initializator=Profiler(domain=input("Enter domain name: "))
    initializator.lookup()
    initializator.result()

