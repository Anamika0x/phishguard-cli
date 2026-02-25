# domain_age.py
import re
from datetime import datetime

def extract_domain_age(whois_data):
    """
    Extracts the domain age from the WHOIS data.
    
    :param whois_data: The raw WHOIS data for the domain
    :return: Domain age in years, or None if it can't be determined
    """
    # Regex to find the domain registration date (Creation Date)
    match = re.search(r"Creation Date: (\d{4}-\d{2}-\d{2})", whois_data)
    
    # If we find the creation date, calculate the age
    if match:
        reg_date = match.group(1)  # Extracts the creation date string
        reg_date = datetime.strptime(reg_date, "%Y-%m-%d")  # Convert to a datetime object
        age = (datetime.now() - reg_date).days // 365  # Calculate age in years
        return age
    
    # If the registration date is not found, return None
    return None
