# PhishGuard CLI

Cybersecurity awareness through automation.

PhishGuard CLI is a phishing detection and risk analysis tool built on Kali Linux using Python.  
It analyzes a given URL and identifies common phishing indicators such as SSL issues, IP-based URLs, domain legitimacy, and basic domain metadata.

This project demonstrates how phishing detection logic can be automated using system-level security tools available in Kali Linux.

---

## Features

- SSL certificate validation
- Detection of IP-based URLs
- WHOIS domain registration verification
- Basic domain age detection
- Automated risk scoring system
- Clean command-line interface

The tool provides a final verdict:

- LOW RISK
- MEDIUM RISK
- HIGH RISK

---

## Demo Output

Example scan:

=== PhishGuard CLI ===

Enter URL (example: https://example.com): http://192.168.1.1

Scanning...

SSL Secure: False  
Using IP instead of domain: True  
Domain registered (WHOIS): True  
Domain Age: None years  

Final Verdict: HIGH RISK  

---

## Tech Stack

- Python 3
- Kali Linux
- WHOIS
- Socket library
- SSL module
- Subprocess automation

---


## Installation

Clone the repository:

```
git clone https://github.com/Anamika0x/phishguard-cli.git
cd phishguard-cli  
```
Install required dependency:

sudo apt install whois  

---

## Usage

Run the tool:

python3 main.py  

Enter a URL when prompted.

Example:

Enter URL: https://google.com  

The tool will scan the URL and display a calculated risk verdict.

---

## How It Works

1. Parses the input URL  
2. Extracts the domain  
3. Attempts SSL handshake verification  
4. Checks whether the URL uses an IP address  
5. Performs WHOIS lookup  
6. Calculates a weighted risk score  
7. Displays final verdict  

The risk score increases if:
- SSL is invalid  
- The URL uses a raw IP  
- Domain is unregistered  
- Domain metadata is suspicious  

---

## ⚠️ Disclaimer

This tool is developed strictly for educational and cybersecurity awareness purposes only.  
Do not use this project for malicious activities.

---
