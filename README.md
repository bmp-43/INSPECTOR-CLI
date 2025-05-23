INQUISITOR 🔍

Inquisitor is a fast, multithreaded cybersecurity toolset in the making — built with speed, precision, and extensibility in mind.

At the moment, Inquisitor ships with a fully functional Port Scanner, with more tools on the way. The goal is to eventually rival professional-grade utilities like Nmap — but with a clean interface, open design, and community-driven growth.
✅ Features

    ⚡ Fast multithreaded port scanning

    🌐 Supports both IP addresses and domain names

    🧠 Configurable timeout, port ranges, and thread count

    📁 External configuration through config_inquisitor.txt

📦 Current Tools
1. Port Scanner

Scans a target for open TCP ports in a given range and prints results in real-time.
Configuration

All settings are managed through the config_inquisitor.txt file:

timeout=0.7  
max_threads=100  
start_port=1  
end_port=100  

Usage

python3 scanner.py

You'll be prompted to enter a target (IP or hostname). Open ports will be printed as they're found.
🚀 What's Next?

    🔒 Hash Identifier

    🌍 Subdomain Finder

    🧠 Common Exploits Reference (auto-matched to open ports)

    🎯 Vulnerability Checker

    💻 CLI / GUI(maybe) dashboard

🧠 Version

Current Version: 0.1.0
This is the first stable alpha with only the port scanner implemented.
📜 License

MIT License — free to use, free to hack on, free to improve.
🤝 Contribute

Want to help improve Inquisitor? PRs and issues are welcome. More docs and modular design coming soon.
⚔️ About

Inquisitor is written by a young developer passionate about cybersecurity and power tools. This is just the beginning.
