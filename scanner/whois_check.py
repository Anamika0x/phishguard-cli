import subprocess
from utils.domain_age import extract_domain_age
from datetime import datetime
import re


def whois_lookup(domain):
    try:
        result = subprocess.check_output(
            ["whois", domain],
            text=True,
            timeout=5
        )

        # Check for invalid domain
        if "No match" in result or "NOT FOUND" in result:
            return False, None

        domain_age = extract_domain_age(result)

        # If domain age is extracted and is less than 1 year, flag as suspicious
        if domain_age and domain_age < 1:
            return False, domain_age

        return True, domain_age

    except:
        return False, None


# NEW: Extract Registrar Information
def get_registrar_info(domain):
    try:
        result = subprocess.check_output(
            ["whois", domain],
            text=True,
            timeout=5
        )

        match = re.search(r"Registrar:\s*(.+)", result)
        if match:
            return match.group(1).strip()

        return "Unknown"

    except:
        return "Unknown"


# NEW: Detect Recent Domain Updates
def detect_recent_update(domain):
    try:
        result = subprocess.check_output(
            ["whois", domain],
            text=True,
            timeout=5
        )

        match = re.search(r"Updated Date:\s*(.+)", result)
        if match:
            update_str = match.group(1).strip()

            try:
                update_date = datetime.strptime(update_str[:10], "%Y-%m-%d")
                days_since_update = (datetime.utcnow() - update_date).days

                if days_since_update < 30:
                    return 1  # recently updated → suspicious
            except:
                pass

        return 0

    except:
        return 0


# NEW: WHOIS Risk Analysis Layer
def analyze_whois_security(domain):
    score = 0

    status, age = whois_lookup(domain)

    if not status:
        score += 2

    if age and age < 1:
        score += 2

    update_risk = detect_recent_update(domain)
    score += update_risk

    return score
