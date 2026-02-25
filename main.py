import socket
import ssl
import urllib.parse
import subprocess


# SSL Certificate Check Function
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except:
        return False


# IP or Domain Check Function
def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True   # It is an IP address
    except:
        return False  # It is a normal domain


# WHOIS Lookup Function
def whois_lookup(domain):
    try:
        result = subprocess.check_output(["whois", domain], text=True)
        if "No match" in result or "NOT FOUND" in result:
            return False
        return True
    except:
        return False


# Risk Scoring Function
def risk_score(ssl_status, is_ip, whois_status):
    score = 0

    if not ssl_status:
        score += 2
    if is_ip:
        score += 2
    if not whois_status:
        score += 1

    if score >= 4:
        return "HIGH RISK"
    elif score >= 2:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# Main function to control flow
def main():
    print("=== PhishGuard CLI ===\n")
    url = input("Enter URL (example: https://example.com): ")

    # Extract the domain from the URL
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    print("\nScanning...\n")

    # Perform the checks
    ssl_status = check_ssl(domain)
    ip_status = check_ip_url(domain)
    whois_status = whois_lookup(domain)

    # Output the results of the checks
    print("SSL Secure:", ssl_status)
    print("Using IP instead of domain:", ip_status)
    print("Domain registered (WHOIS):", whois_status)

    # Calculate and show the final verdict based on the risk score
    result = risk_score(ssl_status, ip_status, whois_status)
    print("\nFinal Verdict:", result)


if __name__ == "__main__":
    main()
import socket
import ssl
import urllib.parse
import subprocess
from utils.domain_age import extract_domain_age  # Import domain age extraction

# SSL Certificate Check Function
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except:
        return False


# IP or Domain Check Function
def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True   # It is an IP address
    except:
        return False  # It is a normal domain


# WHOIS Lookup Function
def whois_lookup(domain):
    try:
        result = subprocess.check_output(["whois", domain], text=True)
        
        # Check for "No match" or "NOT FOUND" to indicate an invalid domain
        if "No match" in result or "NOT FOUND" in result:
            return False, None  # Domain not found, return None for age
        
        # Extract the domain age using the extract_domain_age function
        domain_age = extract_domain_age(result)
        
        # If domain age is extracted and is less than 1 year, flag as suspicious
        if domain_age and domain_age < 1:
            return False, domain_age  # Newly registered
        
        return True, domain_age  # Old domain, return age as well
    except:
        return False, None  # In case of failure


# Risk Scoring Function
def risk_score(ssl_status, is_ip, whois_status, domain_age):
    score = 0

    if not ssl_status:
        score += 2
    if is_ip:
        score += 2
    if not whois_status:
        score += 1
    if domain_age and domain_age < 1:  # Add risk for newly registered domains
        score += 2

    if score >= 4:
        return "HIGH RISK"
    elif score >= 2:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# Main function to control flow
def main():
    print("=== PhishGuard CLI ===\n")
    url = input("Enter URL (example: https://example.com): ")

    # Extract the domain from the URL
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    print("\nScanning...\n")

    # Perform the checks
    ssl_status = check_ssl(domain)
    ip_status = check_ip_url(domain)
    whois_status, domain_age = whois_lookup(domain)

    # Output the results of the checks
    print("SSL Secure:", ssl_status)
    print("Using IP instead of domain:", ip_status)
    
    if whois_status:
        print(f"Domain registered (WHOIS): {whois_status}")
        print(f"Domain Age: {domain_age} years")
    else:
        print("Domain not registered or too new!")

    # Calculate and show the final verdict based on the risk score
    result = risk_score(ssl_status, ip_status, whois_status, domain_age)
    print("\nFinal Verdict:", result)


if __name__ == "__main__":
    main()
