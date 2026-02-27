import requests
from bs4 import BeautifulSoup
from utils.domain_age import extract_domain_age
from scanner.ssl_check import check_ssl
from scanner.domain_check import check_ip_url
from scanner.whois_check import whois_lookup
import urllib.parse

# Suspicious URL Pattern Analysis
def analyze_url_patterns(url, domain):
    score = 0

    if len(url) > 75:  # Long URLs
        score += 1

    if "@" in url:  # If "@" is present in URL (suspicious)
        score += 2

    if url.count("-") > 3:  # Excessive hyphens
        score += 1

    if domain.count(".") > 2:  # Multiple dots in domain name
        score += 1

    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):  # Suspicious TLDs
            score += 2

    return score

# Page Content Analysis
def analyze_page(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check for login forms
        login_fields = soup.find_all("input", {"type": "password"})
        forms = soup.find_all("form")

        suspicious_keywords = [
            "verify your account",
            "urgent action required",
            "login immediately",
            "confirm your identity",
            "bank alert"
        ]
        keyword_flag = any(keyword in response.text.lower() for keyword in suspicious_keywords)

        score = 0
        if login_fields:
            score += 2  # Login form detected (riskier)
        if len(forms) > 3:
            score += 1  # Too many forms could be suspicious
        if keyword_flag:
            score += 1  # Phishing keywords detected

        return score
    except Exception:
        return 1  # Slight suspicion if page can't be fetched

# Full Web Scanner Function
def scan_website(url):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname  # Extract domain safely
    ssl_status = check_ssl(domain)
    ip_status = check_ip_url(domain)
    whois_status, domain_age = whois_lookup(domain)

    url_pattern_score = analyze_url_patterns(url, domain)
    page_content_score = analyze_page(url)

    # Combine scores to get total risk level
    total_score = url_pattern_score + page_content_score

    print(f"\nScanning Website: {url}")
    print(f"SSL Secure: {'Yes' if ssl_status else 'No'}")
    print(f"Using IP Address: {'Yes' if ip_status else 'No'}")
    print(f"WHOIS Registered: {'Yes' if whois_status else 'No'}")
    print(f"Domain Age: {domain_age} years" if domain_age else "Domain Age: Not Available")

    print(f"Suspicious URL Pattern Score: {url_pattern_score}")
    print(f"Content Risk Score: {page_content_score}")
    
    print(f"\nTotal Risk Score: {total_score}")
    
    # Final Verdict
    if total_score > 5:
        print("\nRisk Level: HIGH RISK - Likely Phishing Site")
    elif total_score >= 3:
        print("\nRisk Level: MEDIUM RISK - Potential Phishing Site")
    else:
        print("\nRisk Level: LOW RISK - Legitimate Website")

    return total_score
