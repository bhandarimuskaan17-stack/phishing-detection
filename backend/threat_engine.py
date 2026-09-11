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
    parts = hostname.lower().split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname.lower()


def calculate_threat_score(url, features, ml_probability):

    # --------------------------------------------------
    # 1. ML MODEL SCORE
    # --------------------------------------------------

    # ML probability is directly converted to a 0-100 score.
    # There is NO arbitrary 0.35 multiplier anymore.

    ml_score = round(ml_probability * 100)

    score = ml_score

    reasons = []
    indicators = []

    hostname = features.get("hostname", "")
    base_domain = get_base_domain(hostname)

    # --------------------------------------------------
    # 2. SECURITY EVIDENCE
    # --------------------------------------------------

    security_adjustment = 0

    strong_threat_signals = 0
    warning_signals = 0

    # --------------------------------------------------
    # TRUSTED DOMAIN
    # --------------------------------------------------

    if base_domain in TRUSTED_DOMAINS:

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

        security_adjustment += 8
        warning_signals += 1

        indicators.append({
            "name": "HTTPS",
            "status": "warning",
            "message": "URL does not use HTTPS."
        })

        reasons.append(
            "The website does not use HTTPS."
        )

    # --------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------

    if features["has_ip"] == 1:

        security_adjustment += 20
        strong_threat_signals += 1

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
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    keyword_count = features["suspicious_word_count"]

    if keyword_count > 0:

        keyword_adjustment = min(keyword_count * 6, 24)

        security_adjustment += keyword_adjustment

        if keyword_count >= 3:
            strong_threat_signals += 1
        else:
            warning_signals += 1

        indicators.append({
            "name": "Suspicious Keywords",
            "status": "warning",
            "message": f"{keyword_count} suspicious keyword(s) detected."
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
    # SUBDOMAINS
    # --------------------------------------------------

    if features["num_subdomains"] > 2:

        security_adjustment += 8
        warning_signals += 1

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
    # PUNYCODE
    # --------------------------------------------------

    if features["has_punycode"] == 1:

        security_adjustment += 15
        strong_threat_signals += 1

        indicators.append({
            "name": "Punycode",
            "status": "danger",
            "message": "Internationalized domain encoding detected."
        })

        reasons.append(
            "The domain contains punycode, which can sometimes be "
            "used for deceptive domains."
        )

    # --------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------

    if features["has_suspicious_tld"] == 1:

        security_adjustment += 8
        warning_signals += 1

        indicators.append({
            "name": "Domain Extension",
            "status": "warning",
            "message": "The domain uses a less commonly trusted TLD."
        })

        reasons.append(
            "The domain uses a TLD that can sometimes be associated "
            "with suspicious websites."
        )

    # --------------------------------------------------
    # URL ENCODING
    # --------------------------------------------------

    if features["num_encoded_chars"] > 2:

        security_adjustment += 7
        warning_signals += 1

        indicators.append({
            "name": "URL Encoding",
            "status": "warning",
            "message": "Multiple encoded characters detected."
        })

        reasons.append(
            "The URL contains multiple encoded characters."
        )

    # --------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------

    if features["has_at"] == 1:

        security_adjustment += 15
        strong_threat_signals += 1

        indicators.append({
            "name": "@ Symbol",
            "status": "danger",
            "message": "The URL contains an @ symbol."
        })

        reasons.append(
            "The URL contains an @ symbol, which can be used "
            "to disguise the actual destination."
        )

    # --------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------

    if features["url_length"] > 100:

        security_adjustment += 8
        warning_signals += 1

        indicators.append({
            "name": "URL Length",
            "status": "warning",
            "message": "URL is unusually long."
        })

        reasons.append(
            "The URL is unusually long."
        )

    elif features["url_length"] > 75:

        security_adjustment += 4
        warning_signals += 1

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
    # HYPHENS
    # --------------------------------------------------

    if features["num_hyphens"] > 3:

        security_adjustment += 6
        warning_signals += 1

        indicators.append({
            "name": "Hyphens",
            "status": "warning",
            "message": "URL contains many hyphens."
        })

        reasons.append(
            "The URL contains an unusually high number of hyphens."
        )

    # --------------------------------------------------
    # URL ENTROPY
    # --------------------------------------------------

    # Entropy is deliberately a weak signal because legitimate
    # websites often contain random IDs, tokens and identifiers.

    if features["url_entropy"] > 4.8:

        security_adjustment += 4
        warning_signals += 1

        indicators.append({
            "name": "URL Entropy",
            "status": "warning",
            "message": "URL contains highly irregular character patterns."
        })

        reasons.append(
            "The URL contains unusually random character patterns."
        )

    # --------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------

    if features["num_special_chars"] > 4:

        security_adjustment += 5
        warning_signals += 1

        indicators.append({
            "name": "Special Characters",
            "status": "warning",
            "message": "Many special characters detected."
        })

        reasons.append(
            "The URL contains many special characters."
        )

    # --------------------------------------------------
    # 3. COMBINE ML + SECURITY EVIDENCE
    # --------------------------------------------------

    # Security evidence is an adjustment to the ML score.
    #
    # We cap the adjustment so that a few URL features cannot
    # completely overpower the ML prediction.

    if strong_threat_signals >= 2:

        score += min(security_adjustment, 25)

    elif strong_threat_signals == 1:

        score += min(security_adjustment, 15)

    elif warning_signals >= 2:

        score += min(security_adjustment, 10)

    else:

        score += min(security_adjustment, 5)

    # --------------------------------------------------
    # 4. PROTECT CLEARLY CLEAN TRUSTED DOMAINS
    # --------------------------------------------------

    if (
        base_domain in TRUSTED_DOMAINS
        and strong_threat_signals == 0
        and warning_signals <= 1
    ):

        # A trusted domain with essentially clean URL structure
        # should not become Critical because of an ML false positive.

        score = min(score, 30)

    # --------------------------------------------------
    # 5. STRONG PHISHING COMBINATION
    # --------------------------------------------------

    # Several strong phishing indicators should guarantee
    # a high-risk result.

    if (
        keyword_count >= 4
        and features["has_https"] == 0
    ):

        score = max(score, 85)

    elif (
        keyword_count >= 4
        and strong_threat_signals >= 1
    ):

        score = max(score, 80)

    elif (
        keyword_count >= 2
        and features["has_https"] == 0
    ):

        score = max(score, 65)

    # --------------------------------------------------
    # 6. LIMIT SCORE
    # --------------------------------------------------

    score = max(
        0,
        min(100, round(score))
    )

    # --------------------------------------------------
    # 7. RISK LEVEL
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
    # 8. EXPLANATION
    # --------------------------------------------------

    if not reasons:

        if ml_probability >= 0.70:

            reasons.append(
                "The ML model detected unusual patterns, but no major "
                "suspicious URL indicators were found."
            )

        else:

            reasons.append(
                "No major suspicious URL patterns were detected."
            )

    # --------------------------------------------------
    # 9. RETURN RESULT
    # --------------------------------------------------

    return {
        "threat_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": indicators
    }