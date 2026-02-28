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

## Enhanced Analysis Modules

- URL pattern analysis (length, special characters, suspicious TLDs)
- Domain structure analysis (subdomain abuse detection)
- Numeric trick detection in domains
- Registrar extraction from WHOIS data
- Modular advanced weighted risk scoring
- Risk breakdown transparency

The tool provides a final verdict:

- LOW RISK
- MEDIUM RISK
- HIGH RISK

---

## Demo Output

Example scan:

⚡ PHISHGUARD CLI - ULTRA EDITION ⚡

Choose an option:
1. Scan a website
2. Phishing Awareness Demo
Choice ➜ 1

Enter Target URL ➜ https://google.com

Scanning...

+----------------------+------------------+
| Parameter            | Result           |
+----------------------+------------------+
| SSL Secure           | ✔ Yes            |
| Using IP             | No               |
| WHOIS Registered     | Yes              |
| Domain Age           | 28 years         |
| Registrar            | MarkMonitor Inc. |
| URL Pattern Score    | 0                |
| SSL Risk Score       | 0                |
| WHOIS Risk Score     | 0                |
| Structure Score      | 0                |
| Numeric Trick Score  | 0                |
+----------------------+------------------+

FINAL VERDICT ➜ LOW RISK

> Output may vary depending on domain configuration, SSL status, and scoring parameters.

---


## Enhanced versions may also display:

- Registrar information  
- URL pattern risk score  
- SSL risk score  
- WHOIS risk score  
- Domain structure score  
- Numeric trick score  
- Risk breakdown summary  

---


## Tech Stack

- Python 3
- WHOIS (system tool)
- Socket library
- SSL module
- Subprocess automation
- Modular scanner architecture

### Optional enhancements may use:

- `rich` (for improved CLI output)
- Additional scoring modules

---


## Installation

Clone the repository:

```
git clone https://github.com/Anamika0x/phishguard-cli.git
cd phishguard-cli  
```
Install required dependency (Linux-based systems):

sudo apt install whois  

If additional Python modules are required:

pip install -r requirements.txt

---

## Usage

Run the tool:

python3 main.py  

Enter a URL when prompted.

Example:

Enter URL: https://google.com  

The tool will scan the URL and display a calculated risk verdict along with intermediate detection signals.

---

## How It Works

1. Parses the input URL  
2. Extracts the domain  
3. Attempts SSL handshake verification  
4. Checks whether the URL uses an IP address  
5. Performs WHOIS lookup  
6. Extracts domain age  
7. Applies pattern-based and structural heuristics  
8. Calculates a weighted risk score  
9. Displays final verdict  

The risk score increases if:

- SSL is invalid  
- The URL uses a raw IP  
- Domain is unregistered  
- Domain is newly registered  
- Suspicious URL patterns are detected  
- Domain structure appears manipulated  

---

## 🤝 Contribution

Contributions are welcome.

You can contribute by:

- Improving detection logic
- Enhancing scoring models
- Refactoring modules
- Improving documentation
- Adding new security analysis techniques

Please open an issue before submitting major changes.

## ⚠️ Disclaimer

This tool is developed strictly for educational and cybersecurity awareness purposes only.  
Do not use this project for malicious activities.

The authors are not responsible for misuse of this software.

---