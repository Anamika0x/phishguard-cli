import socket
import ssl
from datetime import datetime


def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except:
        return False


# NEW: Get SSL Certificate Details
def get_ssl_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return None

        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter")

        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days

        return {
            "issuer": issuer.get("organizationName", "Unknown"),
            "expiry_date": expiry_date,
            "days_remaining": days_remaining
        }

    except Exception:
        return None


# NEW: Analyze SSL Security Strength
def analyze_ssl_security(domain):
    score = 0

    details = get_ssl_details(domain)

    if not details:
        return 2  # no certificate details → suspicious

    # Certificate expiring soon
    if details["days_remaining"] < 30:
        score += 1

    # Suspicious issuer (basic heuristic)
    suspicious_issuers = ["Let's Encrypt", "Self-Signed"]

    for issuer in suspicious_issuers:
        if issuer.lower() in details["issuer"].lower():
            score += 1
            break

    return score
