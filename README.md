# ⚠️ Inspector-CLI (v1.x) — DEPRECATED / OUT OF ORDER

Inspector-CLI was an experimental, beginner-friendly cybersecurity toolkit written in Python.  
It included modules for scanning, enumeration, recon, and VirusTotal analysis.  
Over time, the internal design became unstable, unscalable, and too difficult to maintain.

This entire version is now **deprecated**, preserved only for reference and educational purposes.

A complete rebuild under a new project name is underway.

---

## 🚨 Project Status

**Inspector-CLI v1.x is OUT OF ORDER and no longer maintained.**  
No bug fixes, updates, or support will be provided for this version.  
Use at your own risk.

The PyPI package for v1.x will be removed to prevent accidental installs.

---

## 🧩 Features (as implemented in v1.x)

Although deprecated, v1.x included a substantial feature set:

### 🔍 Port Scanning
- Multi-threaded port scanner  
- Banner grabbing for common services  
- Basic vulnerability notes for known ports  
- Hostname/IP validation  
- Adjustable threads, timeout, and port range  

### 🌐 Recon & OSINT
- Subdomain enumeration  
- Directory/path brute-forcing  
- DNS record lookups (A, AAAA, MX, TXT, NS, SOA, CNAME)  
- Domain WHOIS lookup  
- IP WHOIS lookup  
- Reverse DNS lookup  
- Unified Recon & OSINT menu  

### 🦠 Malware Analysis (VirusTotal)
- Hash type recognition (MD5, SHA1, SHA256, SHA512, bcrypt, MySQL5, CRC32)  
- Hash lookup via VirusTotal API  
- URL reputation lookup or submission  
- File scanning with full VT report retrieval  

### ⚙️ Configuration & UX
- Auto-generated `settings.json`  
- Interactive settings editor  
- Built-in usage guide  
- Color-coded info/error messages  
- Logging system (stores scan output)  
- “Full Recon Mode” (chains port scan + recon tools)

---

## ❌ Why v1.x Was Deprecated

Inspector-CLI v1 suffered from several deep architectural flaws:

- tightly coupled internal modules  
- global state interacting unpredictably  
- monkey-patched print/logging logic  
- inconsistent configuration handling  
- menu-based UX not suitable for scaling  
- limited error handling  
- poor testability  
- design choices made before the project had a clear direction  

Fixing these issues would require rewriting 70–80% of the codebase.  
A clean rebuild is faster and safer.

---

## 🔧 Replacement: AegisCLI (In Development)

Inspector-CLI is being replaced by **AegisCLI**, a complete rewrite with:

- Argument-based CLI  
- Modular architecture (scan/enum/dns/vt/etc.)  
- Stable logging and configuration  
- Optional engines (ffuf, gobuster, curl)  
- Clean internal APIs for chaining tools  
- Much improved performance and reliability  
- Extensible long-term design  

AegisCLI will be released as a new PyPI package and repository.

---

## 📦 PyPI Notice

Inspector-CLI v1.x on PyPI will be removed (“yanked”).  
Inspector 2.0 (AegisCLI) will be published cleanly once stable.

---

## 📜 License

Inspector-CLI v1.x remains under **GNU GPL v3.0**.

---

## 🧭 Final Note

Inspector-CLI v1.x was a prototype that served its purpose.  
Its limitations make continued development impossible, but the project laid the foundation for the cleaner, stronger, and more professional AegisCLI.

This repository exists only for archival, reference, and historical interest.
