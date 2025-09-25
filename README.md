# Inspector

Inspector is a beginner-friendly cybersecurity toolkit designed to make common security assessment tasks simple, educational, and accessible. Its modular design helps newcomers understand the basics of cybersecurity, networking, and reconnaissance before moving on to more advanced tools. Inspector emphasizes clarity, ease of use, and practical learning, making it an ideal starting point for anyone new to the field.

---

## Version

**Current version:** `1.1.0`

---

## Features

- 🔍 **Multi-threaded port scanning for speed** <sub>*(since 0.1.0 BETA)*</sub>  
- 🌐 **Fast subdomain enumeration** <sub>*(since 0.2.0 ALPHA)*</sub>  
- 🏷️ **Banner grabbing for open ports** (now grabs banners from all frequently used ports) <sub>*(basic since 0.2.1 BETA, upgraded in 0.2.3 BETA)*</sub>  
- 📂 **Path enumerator (directory brute-forcer)** <sub>*(since 0.2.2)*</sub>  
- 🧠 **Validates hostnames and IP addresses** <sub>*(since 0.1.1 BETA)*</sub>  
- ⚙️ **Configurable settings stored in `settings.json`** (autocreated at first run) <sub>*(replaced `config.txt` in 1.1.0)*</sub>  
- 🛠️ **Modular design for future tools** <sub>*(since 0.2.0 ALPHA)*</sub>  
- 📝 **Displays open ports with descriptions and common vulnerabilities** <sub>*(since 0.1.1 BETA)*</sub>  
- 🦠 **Malware Analyser** (uses VirusTotal for scanning hashes, URLs, and files) <sub>*(hash identifier since 0.3.1 BETA, renamed and upgraded in 0.3.2 BETA)*</sub>  
- 🗂️ **Domain DNS/WHOIS Lookup** <sub>*(added in 0.4.0, improved with DNS resolver in 0.4.1 BETA)*</sub>  
- 🌍 **IP WHOIS Lookup** <sub>*(added in 0.4.2 BETA)*</sub>  
- 🔄 **Reverse DNS Lookup** <sub>*(added in 0.4.2 BETA)*</sub>  
- 🧩 **Unified Recon & OSINT menu** <sub>*(since 0.4.3 BETA)*</sub>  
- 🎨 **Consistent color-coded exception and info messages** <sub>*(since 0.4.3 BETA)*</sub>  
- 📝 **Scan Logging** <sub>*(since 0.5.0 BETA — enabled by default, toggle via `settings.json`)*</sub>  
- 🔗 **Tool Chaining for Full Recon Scan** <sub>*(added in 0.5.1 BETA — run Port Scanner + OSINT tools in one go)*</sub>  
- ⚙️ **Interactive Settings Editor** <sub>*(new in 1.1.0 — edit `settings.json` directly from CLI)*</sub>  
- 📖 **Built-in Guide** <sub>*(new in 1.1.0 — learn how to use Inspector directly from the menu)*</sub>  

---

## Current Toolset

### 🔹 Port Scanner
- Fast and customizable scanning with thread and timeout control  
- Takes an IP or domain as input  
- Prints out open ports, a brief description for each, and common vulnerabilities associated with those ports  
- Includes banner grabbing for all frequently used ports  

### 🔹 Recon & OSINT
- **Subdomain Enumerator**: Quickly finds subdomains for a given domain  
- **Path Enumerator (Directory Brute-Forcer)**: Enumerates directories/paths on web servers to find hidden or sensitive locations  
- **DNS/WHOIS Lookup**: Retrieves DNS and WHOIS information for domains (with DNS resolver integration)  
- **IP WHOIS Lookup**: Retrieves WHOIS information for resolved IP addresses  
- **Reverse DNS Lookup**: Resolves hostnames for IP addresses found  

### 🔹 Malware Analyser
- Uses the VirusTotal API to scan hash values, URLs, and files for malware analysis  

### 🔹 Settings & Guide
- Interactive **settings editor** to configure Inspector without leaving the CLI  
- Built-in **guide** that explains how each tool works and how to use it effectively  

---

## How to Use

1. **Install the package using pip:**

   ```bash
   pip install inspector-cli
   ```

2. **First run will create `settings.json` automatically at:**

   - **Unix/Linux:** `~/.config/inspector-cli/settings.json`  
   - **Windows:** `%AppData%\Inspector-CLI\settings.json`  

   Example `settings.json`:  

   ```json
   {
     "logging_enabled": true,
     "timeout": 0.7,
     "max_threads": 100,
     "start_port": 1,
     "end_port": 1023,
     "vt_api_key": "Your_API_Key"
   }
   ```

3. **Run the toolkit:**

   ```bash
   inspector
   ```

   - Select the tool you want to use (Port Scanner, Recon & OSINT, Full Recon Scan, Malware Analyser, or Settings/Guide).  
   - Follow the prompts for each tool.  
   - For the **Malware Analyser**, register a VirusTotal account and place your API key in `settings.json` or via the CLI editor.  
   - For **Full Recon Scan**, enter a domain and Inspector will automatically chain scanning and recon tools.  

   > **Note:**  
   > - All exception and status messages now use consistent prefixes and color coding.  
   > - **Scan logs are enabled by default** (can be disabled in `settings.json`).  
   > - **Settings editor and guide are new in 1.1.0.**  

---

## Folder Structure

The project folder structure was reorganized in **0.2.0 ALPHA** for better modularity.  
Each core tool now resides in its own directory, making it easier to expand and maintain the toolkit.

---

## Planned

- Plugin support (custom tools via `plugins/` folder)  
- General UX improvements  
- CLI flags for silent/full recon modes  
- New tools and upgrades to existing ones  

---

## License

This project is licensed under the **GNU General Public License v3.0**.  

- You’re free to use, study, share, and modify the code.  
- You must also share your changes under the same license.  
- No one can legally steal or privatize your code.  
- Commercial use is allowed only if they also keep it open-source and credit the original developer.  

📖 Read more: [GNU GPL v3.0](https://www.gnu.org/licenses/gpl)
