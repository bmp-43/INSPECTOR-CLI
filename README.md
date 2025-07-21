# Inspector

Inspector is a beginner-friendly cybersecurity toolkit designed to make common security assessment tasks simple, educational, and accessible. Its modular design helps newcomers understand the basics of cybersecurity, networking, and reconnaissance before moving on to more advanced tools. Inspector emphasizes clarity, ease of use, and practical learning, making it an ideal starting point for anyone new to the field.

## Version

**Current version:** 0.4.3 BETA

## Features

- 🔍 Multi-threaded port scanning for speed  
  <sub>*(since 0.1.0 BETA)*</sub>
- 🌐 Fast subdomain enumeration  
  <sub>*(since 0.2.0 ALPHA)*</sub>
- 🏷️ Banner grabbing for open ports (now grabs banners from all frequently used ports)  
  <sub>*(basic since 0.2.1 BETA, upgraded in 0.2.3 BETA)*</sub>
- 📂 Path enumerator (directory brute-forcer)  
  <sub>*(since 0.2.2)*</sub>
- 🧠 Validates hostnames and IP addresses  
  <sub>*(since 0.1.1 BETA)*</sub>
- ⚙️ Reads config from `config.txt` (port range, timeout, threads)  
  <sub>*(since 0.1.0 BETA)*</sub>
- 🛠️ Modular design for future tools  
  <sub>*(since 0.2.0 ALPHA)*</sub>
- 📝 Displays open ports with descriptions and common vulnerabilities  
  <sub>*(since 0.1.1 BETA)*</sub>
- 🦠 **Malware Analyser** (uses VirusTotal for scanning hashes, URLs, and files)  
  <sub>*(hash identifier since 0.3.1 BETA, renamed and upgraded in 0.3.2 BETA)*</sub>
- 🗂️ **Domain DNS/WHOIS Lookup**  
  <sub>*(added in 0.4.0, improved with DNS resolver in 0.4.1 BETA)*</sub>
- 🌍 **IP WHOIS Lookup**  
  <sub>*(added in 0.4.2 BETA)*</sub>
- 🔄 **Reverse DNS Lookup**  
  <sub>*(added in 0.4.2 BETA)*</sub>
- 🧩 Unified **Recon & OSINT** menu for all reconnaissance tools  
  <sub>*(since 0.4.3 BETA)*</sub>
- 🎨 Consistent color-coded exception and info messages  
  <sub>*(since 0.4.3 BETA)*</sub>

## Current Toolset

- **Port Scanner**
  - Fast and customizable scanning with thread and timeout control
  - Takes an IP or domain as input
  - Prints out open ports, a brief description for each, and common vulnerabilities associated with those ports
  - Includes banner grabbing for all frequently used ports
- **Recon & OSINT**
  - **Subdomain Enumerator**: Quickly finds subdomains for a given domain
  - **Path Enumerator (Directory Brute-Forcer)**: Enumerates directories/paths on web servers to find hidden or sensitive locations
  - **DNS/WHOIS Lookup**: Retrieves DNS and WHOIS information for domains (with DNS resolver integration)
  - **IP WHOIS Lookup**: Retrieves WHOIS information for resolved IP addresses
  - **Reverse DNS Lookup**: Resolves hostnames for IP addresses found
- **Malware Analyser**
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

    - Select the tool you want to use (Port Scanner, Malware Analyser, or Recon & OSINT).
    - Follow the prompts for each tool.
    - For the Port Scanner, enter the IP address or domain to scan.
    - For the Malware Analyser, input the hash string, URL, or file you want to scan.
    - For Recon & OSINT, choose from Subdomain Enumerator, Directory Brute-Forcer, or DNS Profiler (which includes DNS/WHOIS, IP WHOIS, and Reverse DNS lookups).

    > **Note:** All exception and status messages now use consistent prefixes and color coding for clarity.  
    > If you see threading-related warnings or tracebacks when exiting, this is a known Python 3.13 issue and does not affect Inspector's functionality.

## Folder Structure

The project folder structure was reorganized in 0.2.0 ALPHA for better modularity. Each core tool now resides in its own directory, making it easier to expand and maintain the toolkit.

## Planned Tools

- [✓] Banner grabber (now upgraded, grabs banners from all frequently used ports)
- [✓] Path enumerator (directory brute-forcer)
- [✓] Malware analyser (VirusTotal-powered, scans hashes, URLs, and files)
- [✓] WHOIS lookup (added in 0.4.0, improved in 0.4.1 with DNS resolver)
- [✓] Reverse DNS (added in 0.4.2 BETA)
- [✓] IP WHOIS Lookup (added in 0.4.2 BETA)
- [✓] Unified Recon & OSINT menu (since 0.4.3 BETA)
- [✓] Consistent color-coded exception and info messages (since 0.4.3 BETA)
- Future: General Improvements and new tools

## License

This project is licensed under the GNU General Public License v3.0.  
You’re free to use, study, share, and modify the code.  
You must also share your changes under the same license.  
No one can legally steal or privatize your code.  
Commercial use is allowed only if they also keep it open-source.

Read more: https://www.gnu.org/licenses/gpl