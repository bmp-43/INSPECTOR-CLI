import pyfiglet
from colorama import Fore, Style
from tools.scanner import scanner
from tools.enumerator import enumerator
from tools.analyser import analyser
from tools.profiler import profiler

print(f"{Fore.BLUE}-" * 50)
ascii_banner = pyfiglet.figlet_format(f"INSPECTOR")
print(ascii_banner)
print("Version 0.4.1 BETA")
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
            domain = input("Enter domain name: ")
            profiler_instance = profiler.Profiler(domain=domain)
            profiler_instance.lookup()
            profiler_instance.dns_records_fetching()
            profiler_instance.result()
            
        except KeyboardInterrupt:
            print("Shutting down")
    

try:
    while True:
        weapon()
except KeyboardInterrupt:
    print("Shutting Down...")




