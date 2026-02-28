import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import ssl
import urllib.parse
import subprocess
import time
from utils.domain_age import extract_domain_age

from scanner.ssl_check import analyze_ssl_security, get_ssl_details
from scanner.domain_check import analyze_domain_structure, detect_numeric_tricks
from scanner.whois_check import analyze_whois_security, get_registrar_info
from utils.risk_score import advanced_risk_score, risk_breakdown

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


def scanning_animation():
    for i in range(3):
        console.print("[bold red]Scanning" + "." * (i+1))
        time.sleep(0.4)
        console.clear()


def print_welcome_banner():
    banner = """
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔═══██╗██║   ██║
██████╔╝███████║██║███████╗███████║██║   ██║██║   ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║
██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝

        ⚡ PHISHGUARD CLI - ULTRA EDITION ⚡
        Developed by Anamika0x
"""
    console.print(Panel(banner, style="bold red"))


# === ORIGINAL LOGIC (UNCHANGED) ===

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


def whois_lookup(domain):
    try:
        result = subprocess.check_output(
            ["whois", domain],
            text=True,
            timeout=5
        )

        if "No match" in result or "NOT FOUND" in result:
            return False, None

        domain_age = extract_domain_age(result)

        if domain_age is not None and domain_age < 1:
            return False, domain_age

        return True, domain_age

    except Exception:
        return False, None


def analyze_url_patterns(url, domain):
    score = 0

    if len(url) > 75:
        score += 1
    if "@" in url:
        score += 2
    if url.count("-") > 3:
        score += 1
    if domain.count(".") > 2:
        score += 1

    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 2

    return score


def risk_score(ssl_status, is_ip, whois_status, domain_age):
    score = 0
    if not ssl_status:
        score += 2
    if is_ip:
        score += 2
    if not whois_status:
        score += 1
    if domain_age is not None and domain_age < 1:
        score += 2
    return score


def enhanced_risk_engine(base_score, pattern_score):
    total_score = base_score + pattern_score
    if total_score >= 6:
        return "HIGH RISK"
    elif total_score >= 3:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


def phishing_awareness_demo():
    console.print(Panel(
        "⚠️ PHISHING AWARENESS MODE ⚠️\n\n"
        "Common phishing red flags:\n"
        "- Urgent language (\"Act Now!\")\n"
        "- Suspicious domains\n"
        "- Login pages over HTTP\n"
        "- Unexpected attachments\n"
        "- Misspelled brand names\n",
        style="bold yellow"
    ))


#  MAIN FUNCTION
def main():
    console.clear()
    print_welcome_banner()

    choice = console.input(
        "[bold cyan]Choose an option:\n"
        "1. Scan a website\n"
        "2. Phishing Awareness Demo\n"
        "Choice ➜ [/bold cyan]"
    )

    if choice == '1':
        url = console.input("[bold cyan]Enter Target URL ➜ [/bold cyan]").strip()

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname

        if not domain:
            console.print("[bold red]Invalid URL format![/bold red]")
            return

        scanning_animation()

        ssl_status = check_ssl(domain)
        ip_status = check_ip_url(domain)
        whois_status, domain_age = whois_lookup(domain)
        pattern_score = analyze_url_patterns(url, domain)

        ssl_risk_score = analyze_ssl_security(domain)
        ssl_details = get_ssl_details(domain)
        structure_score = analyze_domain_structure(domain)
        numeric_score = detect_numeric_tricks(domain)
        whois_risk_score = analyze_whois_security(domain)
        registrar = get_registrar_info(domain)

        table = Table(title="SCAN RESULTS", box=box.DOUBLE_EDGE)
        table.add_column("Parameter", style="cyan")
        table.add_column("Result", style="magenta")

        table.add_row("SSL Secure", "✔ Yes" if ssl_status else "✘ No")
        table.add_row("Using IP", "Yes" if ip_status else "No")
        table.add_row("WHOIS Registered", "Yes" if whois_status else "Suspicious")
        table.add_row("Domain Age", f"{domain_age} years" if domain_age else "N/A")
        table.add_row("Registrar", str(registrar))
        table.add_row("URL Pattern Score", str(pattern_score))
        table.add_row("SSL Risk Score", str(ssl_risk_score))
        table.add_row("WHOIS Risk Score", str(whois_risk_score))
        table.add_row("Structure Score", str(structure_score))
        table.add_row("Numeric Trick Score", str(numeric_score))

        console.print(table)

        base_score = risk_score(ssl_status, ip_status, whois_status, domain_age)
        result = enhanced_risk_engine(base_score, pattern_score)

        color = "green"
        if result == "MEDIUM RISK":
            color = "yellow"
        elif result == "HIGH RISK":
            color = "bold red"

        console.print(Panel(f"FINAL VERDICT ➜ {result}", style=color))

    elif choice == '2':
        phishing_awareness_demo()

    else:
        console.print("[bold red]Invalid option selected.[/bold red]")


if __name__ == "__main__":
    main()
