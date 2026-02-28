# domain_age.py
import re
from datetime import datetime


def extract_domain_age(whois_data):
    """
    Extracts the domain age from the WHOIS data.
    
    :param whois_data: The raw WHOIS data for the domain
    :return: Domain age in years, or None if it can't be determined
    """

    # Multiple possible date patterns found in WHOIS data
    patterns = [
        r"Creation Date:\s*(\d{4}-\d{2}-\d{2})",
        r"Creation Date:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)",
        r"Created On:\s*(\d{2}-[A-Za-z]{3}-\d{4})",
        r"Registered On:\s*(\d{4}\.\d{2}\.\d{2})",
        r"Domain Create Date:\s*(\d{4}-\d{2}-\d{2})",
        r"creation-date:\s*(\d{4}-\d{2}-\d{2})"
    ]

    for pattern in patterns:
        match = re.search(pattern, whois_data, re.IGNORECASE)
        if match:
            date_str = match.group(1)

            # Try multiple parsing formats safely
            date_formats = [
                "%Y-%m-%d",
                "%Y-%m-%dT%H:%M:%SZ",
                "%d-%b-%Y",
                "%Y.%m.%d"
            ]

            for fmt in date_formats:
                try:
                    reg_date = datetime.strptime(date_str, fmt)
                    age = (datetime.utcnow() - reg_date).days // 365
                    return age
                except:
                    continue

    return None
