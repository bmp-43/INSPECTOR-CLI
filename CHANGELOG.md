# Changelog

All notable changes to this project will be documented in this file.

## [0.4.3 BETA] - 2025-07-21
### Changed
- Unified Enumerator and Profiler under a new menu category: **Recon & OSINT**
- Polished the Port Scanner output formatting and coloring for clarity
- Main menu restructured and styled using consistent color formatting
- Updated all exception messages across tools with consistent formatting and standardized prefixes:
    - `[!]` for errors
    - `[x]` for interruptions
    - `[i]` for neutral info
    - `[?]` for warnings
- Added message clarifying Python 3.13 threading warnings aren't user faults
- Fully commented code for clarity and future

## [0.4.2 BETA] - 2025-07-20
### Added
- **IP WHOIS lookup**: The Profiler tool now fetches and displays WHOIS information for resolved IP addresses.
- **Reverse DNS lookup**: The Profiler tool now performs reverse DNS lookups for all resolved IP addresses.


## [0.4.1 BETA] - 2025-07-18
### Added
- **DNS resolver integration** for the Profiler tool in the DNS/WHOIS Lookup module. The Profiler now fetches and displays DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) for domains.

## [0.4.0] - 2025-07-17
### Added
- **DNS/WHOIS Lookup** tool: Retrieve DNS and WHOIS information for domains. Useful for reconnaissance and domain ownership checks.

### Changed
- Documentation updated to reflect the new DNS/WHOIS Lookup tool and version 0.4.0 BETA


## [0.3.2 BETA] - 2025-07-05
### Changed
- Hash Identifier is now called **Malware Analyser**.
- The tool now uses the VirusTotal API to scan hash values, URLs, and files for malware analysis.

### Added
- Support for scanning URLs and files in addition to hash values via the Malware Analyser tool.

## [0.3.1 BETA] - 2025-06-23
### Added
- Hash Identifier tool: Basic version that detects and identifies hash types (MD5, SHA1, SHA256, etc.).
  - Note: This tool currently only identifies hash types. A significant upgrade is planned for the next version.

### Changed
- Updated documentation to reflect the new tool and beta status.

## [0.3.0] - 2025-06-19
### Changed
- Project renamed from "INQUISITOR" to **Inspector**.
- All references and documentation updated to reflect the new project name.

## [0.2.3 BETA] - 2025-06-12
### Changed
- Banner Grabber upgraded: now attempts to grab banners from all frequently used ports.

### Fixed
- Bug fixes in the subdomain enumerator.

## [0.2.2] - 2025-06-07
### Added
- Path enumerator (directory brute-forcer) tool added and fully functioning.

## [0.2.1 BETA] - 2025-06-04
### Added
- Basic banner grabber integrated into the port scanner.

### Changed
- Port scanner now features syntax highlighting for cleaner logs.

### Fixed
- Minor fixes in the subdomain enumerator.

## [0.2.0 ALPHA] - 2025-06-02
### Added
- Subdomain enumerator tool for fast and efficient subdomain discovery.

### Changed
- Major folder structure rework for better modularity and clarity.

### Fixed
- Port scanner received several bug fixes for improved reliability.

## [0.1.1 BETA] - 2025-05-27
### Changed
- Port scanner updated for faster scanning.
- Added display of brief explanations for each port and its possible vulnerabilities.

## [0.1.0 BETA] - 2025-05-23
### Added
- Initial release.
- Basic multi-threaded port scanner.
