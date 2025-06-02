# INQUISITOR

INQUISITOR is a modular cybersecurity toolkit aimed at making common security assessment tasks easier to perform and extend. It currently features a multi-threaded port scanner and a subdomain enumerator.

## What's New in 0.2.0 ALPHA

- Added a subdomain enumerator tool for fast and efficient subdomain discovery.
- Major folder structure rework for better modularity and clarity.
- Port scanner received several bug fixes for improved reliability.

## Features

- 🔍 Multi-threaded port scanning for speed
- 🌐 Fast subdomain enumeration
- 🧠 Validates hostnames and IP addresses
- ⚙️ Reads config from `config_inquisitor.txt` (port range, timeout, threads)
- 🛠️ Modular design for future tools
- 📝 Displays open ports with descriptions and common vulnerabilities

## Current Toolset

- **Port Scanner**
  - Fast and customizable scanning with thread and timeout control
  - Takes an IP or domain as input
  - Prints out open ports, a brief description for each, and common vulnerabilities associated with those ports
- **Subdomain Enumerator**
  - Quickly finds subdomains for a given domain
  - Useful for recon and expanding your attack surface analysis

## How to Use

1. Clone the repo:
    ```bash
    git clone https://github.com/bmp-43/INQUISITOR.git
    cd INQUISITOR
    ```

2. Make sure `config_inquisitor.txt` exists with values like:
    ```
    timeout=0.7
    max_threads=100
    start_port=1
    end_port=100
    ```

3. Run the toolkit:
    ```bash
    python3 inquisitor.py
    ```

    - Select the tool you want to use (Port Scanner or Subdomain Enumerator).
    - Follow the prompts for each tool.
    - For the Port Scanner, enter the IP address or domain to scan.
    - For the Subdomain Enumerator, enter the domain to enumerate.

## Folder Structure

The project folder structure was reorganized in 0.2.0 ALPHA for better modularity. Each core tool now resides in its own directory, making it easier to expand and maintain the toolkit.

## Planned Tools

- Banner grabber
- Hash identifier
- Directory brute-forcer
- IP geolocator
- WHOIS lookup
- Reverse DNS
- Future: Exploit suggestions based on open ports

## License

This project is licensed under the GNU General Public License v3.0.  
You’re free to use, study, share, and modify the code.  
You must also share your changes under the same license.  
No one can legally steal or privatize your code.  
Commercial use is allowed only if they also keep it open-source.

Read more: https://www.gnu.org/licenses/gpl-3.0.en.html

