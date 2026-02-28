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


# NEW: Advanced Weighted Risk Scoring
def advanced_risk_score(
    ssl_status,
    is_ip,
    whois_status,
    domain_age=None,
    url_pattern_score=0,
    ssl_risk_score=0,
    whois_risk_score=0,
    structure_score=0,
    numeric_score=0
):
    score = 0

    # Core signals
    if not ssl_status:
        score += 2
    if is_ip:
        score += 2
    if not whois_status:
        score += 2

    # Domain age factor
    if domain_age is not None and domain_age < 1:
        score += 2

    # Additional modules
    score += url_pattern_score
    score += ssl_risk_score
    score += whois_risk_score
    score += structure_score
    score += numeric_score

    # Final classification
    if score >= 8:
        return "HIGH RISK"
    elif score >= 4:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


# NEW: Risk Score Breakdown (For Debug / Transparency)
def risk_breakdown(
    ssl_status,
    is_ip,
    whois_status,
    domain_age=None
):
    breakdown = {}

    breakdown["SSL"] = 0 if ssl_status else 2
    breakdown["IP Usage"] = 2 if is_ip else 0
    breakdown["WHOIS"] = 0 if whois_status else 2
    breakdown["New Domain"] = 2 if (domain_age is not None and domain_age < 1) else 0

    breakdown["Total"] = sum(breakdown.values())

    return breakdown
