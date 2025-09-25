# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2025-09-25

### ✨ Added
- **Interactive Settings Editor:** Users can now edit configuration directly from the CLI.  
- **Built-in Guide:** Added a step-by-step usage guide accessible from the main menu.  

### 🔄 Changed
- **Config system overhaul:** Replaced legacy `config.txt` with `settings.json`.  
  - Autocreated on first run.  
  - Stored at:  
    - **Unix/Linux:** `~/.config/inspector-cli/settings.json`  
    - **Windows:** `%AppData%\Inspector-CLI\settings.json`  

### 🗑️ Removed
- Old `config.txt` support fully removed.

## [1.0.0] - 2025-07-30

### 🎉 Major Release: Inspector CLI is now pip-installable

Inspector CLI v1.0.0 marks its first stable release — fully refactored, pip-distributable, and ready for real-world use.

### 🧱 Added

- `setup.py` for pip installation and global CLI access (`inspector`)
- Automatic first-run config generation to `~/.config/inspector-cli/config.txt`
- Auto-patching system: missing config keys are restored during runtime
- Clean entry point (`__main__.py`) for `python -m inspector_cli`

### 🔄 Changed

- All tools now receive a centralized `settings` dictionary instead of loading config independently
- Removed duplicated `config()` logic from every tool
- Updated all file access to be relative and safe across platforms

### 🧼 Fixed

- ThreadPoolExecutor Ctrl+C crashes in `scanner`
- asyncio `CancelledError` and pending task spam in `enumerator`
- Cleaned up exception handling for all tools (user-friendly shutdown)
- Fully suppressed Python 3.13's atexit and shutdown traceback noise

### 📦 Packaging Notes

- Package name: `inspector-cli`
- CLI command: `inspector`
- Python: `>=3.8` (tested on 3.13)



## \[0.5.1 BETA] - 2025-07-26

### Added

* **Full Reconnaissance Scan:** New module added in the main menu allowing users to perform a full recon chain on a specified IP or domain. It runs Port Scanner + OSINT tools in one pass.

### Fixed

* **Logging bug:** Fixed issue where dummy result files could be created even if no scans were run.
* **SSL port bug:** Port Scanner now properly handles SSL ports where banners could not be retrieved.

### Changed

* Overall improvement in code structure for better scalability.
* Minor changes and cleanups across multiple modules.

## \[0.5.0 BETA] - 2025-07-23

### Added

* **Scan logging:** Inspector now logs all scans performed by the user. Each scan session is saved to a timestamped file in the `results` directory.
* **Configurable logging:** Logging is enabled by default, but can be easily disabled by setting `logging_enabled=False` in `config.txt`.

### Changed

* File inspector.py got serious architechture changes.

## \[0.4.3 BETA] - 2025-07-21

### Changed

* Unified Enumerator and Profiler under a new menu category: **Recon & OSINT**
* Polished the Port Scanner output formatting and coloring for clarity
* Main menu restructured and styled using consistent color formatting
* Updated all exception messages across tools with consistent formatting and standardized prefixes:

  * `[!]` for errors
  * `[x]` for interruptions
  * `[i]` for neutral info
  * `[?]` for warnings
* Added message clarifying Python 3.13 threading warnings aren't user faults
* Fully commented code for clarity and future

## \[0.4.2 BETA] - 2025-07-20

### Added

* **IP WHOIS lookup:** The Profiler tool now fetches and displays WHOIS information for resolved IP addresses.
* **Reverse DNS lookup:** The Profiler tool now performs reverse DNS lookups for all resolved IP addresses.

## \[0.4.1 BETA] - 2025-07-18

### Added

* **DNS resolver integration** for the Profiler tool in the DNS/WHOIS Lookup module. The Profiler now fetches and displays DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) for domains.

## \[0.4.0 BETA] - 2025-07-17

### Added

* **DNS/WHOIS Lookup** tool: Retrieve DNS and WHOIS information for domains. Useful for reconnaissance and domain ownership checks.

### Changed

* Documentation updated to reflect the new DNS/WHOIS Lookup tool and version 0.4.0 BETA

## \[0.3.2 BETA] - 2025-07-05

### Changed

* Hash Identifier is now called **Malware Analyser**.
* The tool now uses the VirusTotal API to scan hash values, URLs, and files for malware analysis.

### Added

* Support for scanning URLs and files in addition to hash values via the Malware Analyser tool.

## \[0.3.1 BETA] - 2025-06-23

### Added

* Hash Identifier tool: Basic version that detects and identifies hash types (MD5, SHA1, SHA256, etc.).

  * Note: This tool currently only identifies hash types. A significant upgrade is planned for the next version.

### Changed

* Updated documentation to reflect the new tool and beta status.

## \[0.3.0 BETA] - 2025-06-19

### Changed

* Project renamed from "INQUISITOR" to **Inspector**.
* All references and documentation updated to reflect the new project name.

## \[0.2.3 BETA] - 2025-06-12

### Changed

* Banner Grabber upgraded: now attempts to grab banners from all frequently used ports.

### Fixed

* Bug fixes in the subdomain enumerator.

## \[0.2.2 BETA] - 2025-06-07

### Added

* Path enumerator (directory brute-forcer) tool added and fully functioning.

## \[0.2.1 BETA] - 2025-06-04

### Added

* Basic banner grabber integrated into the port scanner.

### Changed

* Port scanner now features syntax highlighting for cleaner logs.

### Fixed

* Minor fixes in the subdomain enumerator.

## \[0.2.0 ALPHA] - 2025-06-02

### Added

* Subdomain enumerator tool for fast and efficient subdomain discovery.

### Changed

* Major folder structure rework for better modularity and clarity.

### Fixed

* Port scanner received several bug fixes for improved reliability.

## \[0.1.1 BETA] - 2025-05-27

### Changed

* Port scanner updated for faster scanning.
* Added display of brief explanations for each port and its possible vulnerabilities.

## \[0.1.0 BETA] - 2025-05-23

### Added

* Initial release.
* Basic multi-threaded port scanner.
