# INQUISITOR

INQUISITOR is a powerful, multi-threaded port scanning tool designed for speed, clarity, and future modular expansion. Currently, it includes a high-performance port scanner with configuration file support.

## Features

- 🔍 Scan ports quickly with multithreading  
- 🧠 Validates hostnames and IP addresses  
- ⚙️ Reads config from `config_inquisitor.txt` (port range, timeout, threads)  
- 📄 Clean and modular codebase ready to grow  

## Current Toolset

- **Port Scanner**  
  A fast and customizable port scanner with thread control and timeout settings. Useful for recon, auditing, and testing open ports on any target.

## How to Use

1. Clone the repo  
2. Make sure `config_inquisitor.txt` exists and has values like:
    ```
    timeout=0.7  
    max_threads=100  
    start_port=1  
    end_port=100
    ```
3. Run:
    ```bash
    python scanner.py
    ```

## Planned Tools

- Banner grabber  
- Hash identifier  
- Directory brute-forcer  
- IP geolocator  
- WHOIS lookup  
- Reverse DNS  
- Future: Exploit suggestions based on open ports

## License

This project is licensed under the **GNU General Public License v3.0**.  
This means:
- You’re free to use, study, share, and modify the code  
- **You must also share your changes under the same license**  
- No one can legally steal or privatize your code  
- Commercial use is allowed only if they also keep it open-source  

Read more: https://www.gnu.org/licenses/gpl-3.0.en.html

