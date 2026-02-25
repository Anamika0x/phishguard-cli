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
