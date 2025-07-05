# Inspector

Inspector is a modular cybersecurity toolkit aimed at making common security assessment tasks easier to perform and extend. It currently features a multi-threaded port scanner, a subdomain enumerator, a path enumerator, a banner grabber, and a **Malware Analyser** (formerly Hash Identifier) that uses the VirusTotal API for scanning.

## Features

- 🔍 Multi-threaded port scanning for speed
- 🌐 Fast subdomain enumeration
- 🏷️ Banner grabbing for open ports (now grabs banners from all frequently used ports)
- 📂 Path enumerator (directory brute-forcer)
- 🧠 Validates hostnames and IP addresses
- ⚙️ Reads config from `config.txt` (port range, timeout, threads)
- 🛠️ Modular design for future tools
- 📝 Displays open ports with descriptions and common vulnerabilities
- 🦠 **Malware Analyser** (uses VirusTotal for scanning hashes, URLs, and files)

## Current Toolset

- **Port Scanner**
  - Fast and customizable scanning with thread and timeout control
  - Takes an IP or domain as input
  - Prints out open ports, a brief description for each, and common vulnerabilities associated with those ports
  - Includes banner grabbing for all frequently used ports
- **Subdomain Enumerator**
  - Quickly finds subdomains for a given domain
  - Useful for recon and expanding your attack surface analysis
- **Banner Grabber**
  - Integrated with the port scanner
  - Fetches service banners from all frequently used ports
- **Path Enumerator (Directory Brute-Forcer)**
  - Enumerates directories/paths on web servers to find hidden or sensitive locations
- **Malware Analyser** (formerly Hash Identifier)
  - Uses the VirusTotal API to scan hash values, URLs, and files for malware analysis

## How to Use

1. Clone the repo:
    ```bash
    git clone https://github.com/bmp-43/Inspector.git
    cd Inspector
    ```

2. Make sure `config_inspector.txt` exists with values like:
    ```
    timeout=0.7
    max_threads=100
    start_port=1
    end_port=100
    ```

3. If you will use the Malware Analyser, set up your VirusTotal API key as instructed in the tool's documentation or config.

4. Run the toolkit:
    ```bash
    python3 inspector.py
    ```

    - Select the tool you want to use (Port Scanner, Subdomain Enumerator, Path Enumerator, Banner Grabber, or Malware Analyser).
    - Follow the prompts for each tool.
    - For the Port Scanner, enter the IP address or domain to scan.
    - For the Subdomain Enumerator, enter the domain to enumerate.
    - For the Path Enumerator, enter the target URL/domain to brute-force directories.
    - For the Malware Analyser, input the hash string, URL, or file you want to scan.

## Folder Structure

The project folder structure was reorganized in 0.2.0 ALPHA for better modularity. Each core tool now resides in its own directory, making it easier to expand and maintain the toolkit.

## Planned Tools

- [✓] Banner grabber (now upgraded, grabs banners from all frequently used ports)
- [✓] Path enumerator (directory brute-forcer)
- [✓] Malware analyser (VirusTotal-powered, scans hashes, URLs, and files)
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
