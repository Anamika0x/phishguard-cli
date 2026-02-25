import socket
import ssl
import urllib.parse
import subprocess
from utils.domain_age import extract_domain_age


# SSL Certificate Check Function
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


# IP or Domain Check Function
def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


# WHOIS Lookup Function
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

        # Fix for 0-year bug
        if domain_age is not None and domain_age < 1:
            return False, domain_age

        return True, domain_age

    except Exception:
        return False, None


# Risk Scoring Function
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

    if score >= 4:
        return "HIGH RISK"
    elif score >= 2:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# Main function
def main():
    print("=== PhishGuard CLI ===\n")

    url = input("Enter URL (example: https://example.com): ").strip()

    # Ensure scheme exists
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname  # safer than netloc

    if not domain:
        print("Invalid URL format.")
        return

    print("\nScanning...\n")

    ssl_status = check_ssl(domain)
    ip_status = check_ip_url(domain)
    whois_status, domain_age = whois_lookup(domain)

    print(f"SSL Secure: {'Yes' if ssl_status else 'No'}")
    print(f"Using IP Address: {'Yes' if ip_status else 'No'}")

    if whois_status:
        print("WHOIS Registered: Yes")
        if domain_age is not None:
            print(f"Domain Age: {domain_age} years")
    else:
        print("WHOIS Registered: No or Suspicious")

    result = risk_score(ssl_status, ip_status, whois_status, domain_age)

    print(f"\nFinal Verdict: {result}")


if __name__ == "__main__":
    main()