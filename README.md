#inquisitor

INQUISITOR is a universal cybersecurity toolkit for professionals, designed to be modular, fast, and easy to expand. Its first tool, a powerful multi-threaded port scanner, helps users quickly assess network targets and learn about common vulnerabilities.
Features

    🔍 Multi-threaded port scanning for speed
    🧠 Validates hostnames and IP addresses
    ⚙️ Reads config from config_inquisitor.txt (port range, timeout, threads)
    🛠️ Modular design for future tools
    📝 Displays open ports with descriptions and common vulnerabilities

Current Toolset

    Port Scanner
        Fast and customizable scanning with thread and timeout control
        Takes an IP or domain as input
        Prints out open ports, a brief description for each, and common vulnerabilities associated with those ports

How to Use

    Clone the repo:
    bash

git clone https://github.com/bmp-43/INQUISITOR.git
cd INQUISITOR

Make sure config_inquisitor.txt exists with values like:
Code

timeout=0.7
max_threads=100
start_port=1
end_port=100

Run the toolkit:
bash

    python3 inquisitor.py

    Select the tool you want to use (currently only Port Scanner is available).
    When prompted, enter the IP address or domain you want to scan.
    View the list of open ports, each with a description and info about common vulnerabilities.

Planned Tools

    Banner grabber
    Subdomain enumeration tool
    Hash identifier
    Directory brute-forcer
    IP geolocator
    WHOIS lookup
    Reverse DNS
    Future: Exploit suggestions based on open ports

License

This project is licensed under the GNU General Public License v3.0.
You’re free to use, study, share, and modify the code.
You must also share your changes under the same license.
No one can legally steal or privatize your code.
Commercial use is allowed only if they also keep it open-source.

Read more: https://www.gnu.org/licenses/gpl-3.0.en.html

