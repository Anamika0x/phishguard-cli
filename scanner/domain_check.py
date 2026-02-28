import socket
import ipaddress


def check_ip_url(domain):
    try:
        socket.inet_aton(domain)
        return True   # It is an IPv4 address
    except:
        pass

    try:
        ipaddress.IPv6Address(domain)
        return True   # It is an IPv6 address
    except:
        pass

    return False  # It is a normal domain


# NEW: Detect Suspicious Subdomain Patterns
def analyze_domain_structure(domain):
    score = 0

    # Too many subdomains (e.g., login.secure.verify.bank.com.fake.tk)
    if domain.count(".") > 3:
        score += 1

    # Excessive hyphens
    if domain.count("-") > 3:
        score += 1

    # Suspicious keywords inside domain
    suspicious_keywords = [
        "login",
        "secure",
        "verify",
        "update",
        "account",
        "banking"
    ]

    for keyword in suspicious_keywords:
        if keyword in domain.lower():
            score += 1
            break

    return score


# NEW: Detect Numeric or Encoded Tricks
def detect_numeric_tricks(domain):
    score = 0

    # Domain mostly numbers
    if domain.replace(".", "").isdigit():
        score += 2

    # Very long domain
    if len(domain) > 50:
        score += 1

    return score
