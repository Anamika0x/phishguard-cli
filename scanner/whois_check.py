import subprocess
from utils.domain_age import extract_domain_age

def whois_lookup(domain):
    try:
        # Run the WHOIS command and get the result
        result = subprocess.check_output(["whois", domain], text=True)
        
        # Check for "No match" or "NOT FOUND" to indicate an invalid domain
        if "No match" in result or "NOT FOUND" in result:
            return False, None
        
        # Extract the domain age using the extract_domain_age function
        domain_age = extract_domain_age(result)
        
        # If domain age is extracted and is less than 1 year, flag as suspicious
        if domain_age and domain_age < 1:
            return False, domain_age  # Newly registered
        
        # If WHOIS lookup is successful and domain age is valid
        return True, domain_age  # Old domain

    except:
        return False, None
