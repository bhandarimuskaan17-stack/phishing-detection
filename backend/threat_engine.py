TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "amazon.com",
    "amazon.in",
    "microsoft.com",
    "apple.com",
    "github.com",
    "linkedin.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
}


def get_base_domain(hostname):
    """
    Get the main domain from a hostname.
    """

    parts = hostname.lower().split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname.lower()


def calculate_threat_score(url, features, ml_probability):
    """
    Combine machine-learning prediction with
    security heuristics to produce a final threat score.
    """

    score = ml_probability * 100

    reasons = []
    indicators = []

    # --------------------------------------------------
    # Trusted domain check
    # --------------------------------------------------

    hostname = features.get("hostname", "")

    base_domain = get_base_domain(hostname)

    if base_domain in TRUSTED_DOMAINS:

        score -= 65

        indicators.append({
            "name": "Trusted Domain",
            "status": "pass",
            "message": "Domain matches a commonly trusted website."
        })

    # --------------------------------------------------
    # HTTPS
    # --------------------------------------------------

    if features["has_https"] == 1:

        indicators.append({
            "name": "HTTPS",
            "status": "pass",
            "message": "Connection uses HTTPS."
        })

    else:

        score += 8

        indicators.append({
            "name": "HTTPS",
            "status": "warning",
            "message": "URL does not use HTTPS."
        })

        reasons.append(
            "The website does not use HTTPS."
        )

    # --------------------------------------------------
    # IP address
    # --------------------------------------------------

    if features["has_ip"] == 1:

        score += 25

        indicators.append({
            "name": "IP Address",
            "status": "danger",
            "message": "URL uses an IP address instead of a domain."
        })

        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    else:

        indicators.append({
            "name": "IP Address",
            "status": "pass",
            "message": "URL uses a normal domain."
        })

    # --------------------------------------------------
    # Suspicious words
    # --------------------------------------------------

    if features["suspicious_word_count"] > 0:

        score += min(
            features["suspicious_word_count"] * 8,
            24
        )

        indicators.append({
            "name": "Suspicious Keywords",
            "status": "warning",
            "message": (
                f"{features['suspicious_word_count']} "
                "suspicious keyword(s) detected."
            )
        })

        reasons.append(
            "The URL contains words commonly associated with phishing."
        )

    else:

        indicators.append({
            "name": "Suspicious Keywords",
            "status": "pass",
            "message": "No common phishing keywords detected."
        })

    # --------------------------------------------------
    # Subdomains
    # --------------------------------------------------

    if features["num_subdomains"] > 2:

        score += 12

        indicators.append({
            "name": "Subdomains",
            "status": "warning",
            "message": "URL contains multiple subdomains."
        })

        reasons.append(
            "The URL contains an unusually large number of subdomains."
        )

    else:

        indicators.append({
            "name": "Subdomains",
            "status": "pass",
            "message": "Subdomain structure looks normal."
        })

    # --------------------------------------------------
    # Punycode
    # --------------------------------------------------

    if features["has_punycode"] == 1:

        score += 20

        indicators.append({
            "name": "Punycode",
            "status": "danger",
            "message": "Internationalized domain encoding detected."
        })

        reasons.append(
            "The domain contains punycode, which can sometimes be used for deceptive domains."
        )

    # --------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------

    if features["has_suspicious_tld"] == 1:

        score += 12

        indicators.append({
            "name": "Domain Extension",
            "status": "warning",
            "message": "The domain uses a less commonly trusted TLD."
        })

        reasons.append(
            "The domain uses a TLD that is sometimes associated with suspicious websites."
        )

    # --------------------------------------------------
    # URL encoding
    # --------------------------------------------------

    if features["num_encoded_chars"] > 2:

        score += 10

        indicators.append({
            "name": "URL Encoding",
            "status": "warning",
            "message": "Multiple encoded characters detected."
        })

        reasons.append(
            "The URL contains multiple encoded characters."
        )

    # --------------------------------------------------
    # @ symbol
    # --------------------------------------------------

    if features["has_at"] == 1:

        score += 18

        indicators.append({
            "name": "@ Symbol",
            "status": "danger",
            "message": "The URL contains an @ symbol."
        })

        reasons.append(
            "The URL contains an @ symbol, which can be used to disguise the actual destination."
        )

    # --------------------------------------------------
    # URL length
    # --------------------------------------------------

    if features["url_length"] > 100:

        score += 12

        indicators.append({
            "name": "URL Length",
            "status": "warning",
            "message": "URL is unusually long."
        })

        reasons.append(
            "The URL is unusually long."
        )

    elif features["url_length"] > 75:

        score += 6

        indicators.append({
            "name": "URL Length",
            "status": "warning",
            "message": "URL is longer than normal."
        })

    else:

        indicators.append({
            "name": "URL Length",
            "status": "pass",
            "message": "URL length looks normal."
        })

    # --------------------------------------------------
    # Hyphens
    # --------------------------------------------------

    if features["num_hyphens"] > 3:

        score += 8

        indicators.append({
            "name": "Hyphens",
            "status": "warning",
            "message": "URL contains many hyphens."
        })

        reasons.append(
            "The URL contains an unusually high number of hyphens."
        )

    # --------------------------------------------------
    # Entropy
    # --------------------------------------------------

    if features["url_entropy"] > 4.5:

        score += 10

        indicators.append({
            "name": "URL Entropy",
            "status": "warning",
            "message": "URL contains highly irregular character patterns."
        })

        reasons.append(
            "The URL contains unusually random character patterns."
        )

    # --------------------------------------------------
    # Special characters
    # --------------------------------------------------

    if features["num_special_chars"] > 4:

        score += 8

        indicators.append({
            "name": "Special Characters",
            "status": "warning",
            "message": "Many special characters detected."
        })

    # --------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------

    score = max(
        0,
        min(
            100,
            round(score)
        )
    )

    # --------------------------------------------------
    # Risk level
    # --------------------------------------------------

    if score >= 85:

        risk_level = "Critical"

    elif score >= 65:

        risk_level = "High"

    elif score >= 35:

        risk_level = "Medium"

    else:

        risk_level = "Low"

    # --------------------------------------------------
    # Default reason
    # --------------------------------------------------

    if not reasons:

        reasons.append(
            "No major suspicious URL patterns were detected."
        )

    return {
        "threat_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": indicators
    }