import pyfiglet
from tools.scanner import scanner
from tools.enumerator import enumerator
from colorama import Fore, Style
from tools.analyser import analyser
print(f"{Fore.BLUE}-" * 50)
ascii_banner = pyfiglet.figlet_format(f"INSPECTOR")
print(ascii_banner)
print("Version 0.3.2 BETA")
print("-" * 50)

scanner_instance = scanner.PortScanner()


def weapon():
    mode = input(f"{Style.RESET_ALL}Pick the tool you wanna use: \n 1. Port Scanner\n 2. Enumerator\n 3. Malware Analyser \n")
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
    elif mode == "3" or mode.lower() == "Malware Analyser":
        try:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}Note that Malware analyser uses VirusTotal API. Check the config.txt{Style.RESET_ALL}")
            analyser.main()
        except KeyboardInterrupt:
            print("Shutting down") 

try:
    while True:
        weapon()
except KeyboardInterrupt:
    print("Shutting Down...")




