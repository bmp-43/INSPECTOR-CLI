import pyfiglet
from colorama import Fore, Style
from tools.scanner import scanner
from tools.enumerator import enumerator
from tools.analyser import analyser
from tools.profiler import profiler

print(f"{Fore.BLUE}-" * 50)
ascii_banner = pyfiglet.figlet_format(f"INSPECTOR")
print(ascii_banner)
print("Version 0.4.2 BETA")
print("-" * 50)

scanner_instance = scanner.PortScanner()


def weapon():
    mode = input(f"{Style.RESET_ALL}Pick the tool you wanna use: \n 1. Port Scanner\n 2. Enumerator\n 3. Malware Analyser \n 4. Profiler \n")
    if mode == "1" or mode.lower() == "port scanner":
        try:
            scanner_instance.scan_port()
        except KeyboardInterrupt:
            print("Shutting down")
    elif mode == "2" or mode.lower() == "enumerator":
        try:
            enumerator.tool()
        except KeyboardInterrupt:
            print("Shutting down")        
    elif mode == "3" or mode.lower() == "malware analyser":
        try:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Note that Malware analyser uses VirusTotal API. Check the config.txt{Style.RESET_ALL}")
            analyser.main()
        except KeyboardInterrupt:
            print("Shutting down") 
    elif mode == "4" or mode.lower() == "domain profiler":
        try:
            initializator=profiler.Profiler(domain=input("Enter domain name: "))
            initializator.domain_lookup()
            initializator.dns_records_fetching()
            initializator.ip_loookup()
            initializator.reverse_dns()
            initializator.result()
            
        except KeyboardInterrupt:
            print("Shutting down")
    

try:
    while True:
        weapon()
except KeyboardInterrupt:
    print("Shutting Down...")




