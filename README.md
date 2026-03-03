# PhishGuard CLI

Cybersecurity awareness through automation.

PhishGuard CLI is a phishing detection and risk analysis tool built on Kali Linux using Python.  
It analyzes a given URL and identifies common phishing indicators such as SSL issues, IP-based URLs, domain legitimacy, and basic domain metadata.

This project demonstrates how phishing detection logic can be automated using system-level security tools available in Kali Linux.

---

## Features

- SSL certificate validation (real-time handshake check)
- Detection of IP-based URLs
- WHOIS domain registration verification
- Domain age extraction from WHOIS data
- Registrar detection
- URL pattern-based anomaly scoring
- Suspicious TLD flagging
- Subdomain abuse detection
- Numeric trick detection (e.g., g00gle-style spoofing)
- Weighted modular risk scoring engine
- Structured CLI output (Ultra Edition mode)

## Enhanced Analysis Modules

- URL length analysis
- Special character density check
- Suspicious TLD identification
- Deep subdomain structure analysis
- Registrar extraction from WHOIS metadata
- SSL validation scoring
- Domain age-based trust modeling
- Transparent risk breakdown summary

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
3. Phishing Kit (Lab / Research)
   
Ctrl+C to Exit

Choice ➜ 1

Enter Target URL ➜ https://google.com

Scanning...


### Scan Results

| Parameter            | Result           |
|----------------------|------------------|
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


FINAL VERDICT ➜ LOW RISK

> Output may vary depending on domain configuration, SSL status, and scoring parameters.

---


## Additional Output Modes

- Depending on configuration and enhancements, the tool may also display:
- Detailed risk breakdown table
- Weighted score contribution per module
- Pattern anomaly reasoning
- Awareness simulation output (Demo Mode)

---


## Tech Stack

- Python 3
- WHOIS (system tool)
- Socket library
- SSL module
- Subprocess automation
- Modular scanner architecture

### Optional enhancements may use:

- `rich` (enhanced CLI visuals)
- Colored terminal output
- Extended scoring modules

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
2. Extracts and normalizes the domain
3. Performs SSL handshake validation
4. Checks for raw IP usage
5. Executes WHOIS lookup via system tool
6. Extracts domain age & registrar
7. Applies URL pattern heuristics
8. Detects numeric substitution tricks
9. Analyzes subdomain structure
10. Calculates weighted risk score
11. Displays structured verdict

The risk score increases if:

- SSL verification fails
- The URL uses a raw IP address
- WHOIS data is missing or domain is unregistered
- Domain age is extremely new
- Suspicious URL patterns are detected
- Excessive subdomains are present
- Numeric character spoofing is detected

---

## 🤝 Contribution

Contributions are welcome.

You can contribute by:

- Improving detection heuristics
- Enhancing risk transparency
- Refactoring scanner modules
- Improving CLI UX
- Adding new security analysis techniques

Please open an issue before submitting major changes.

## ⚠️ Disclaimer

This tool is developed strictly for educational and cybersecurity awareness purposes only.  
Do not use this project for malicious activities.

The maintainers are not responsible for misuse of this software.

---
