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
    if not hostname:
        return ""

    parts = hostname.lower().split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return hostname.lower()


def calculate_threat_score(url, features, ml_probability):
    """
    Hybrid phishing threat scoring.

    The final score combines:
    - Machine-learning prediction
    - Interpretable URL security indicators

    Weak indicators have limited influence.
    Strong combinations can still produce Critical risk.
    """

    # =========================================================
    # 1. MACHINE LEARNING SCORE
    # =========================================================

    ml_score = round(ml_probability * 100)

    # ML has strong influence, but does NOT completely determine
    # the final score.
    score = round(ml_score * 0.65)

    # =========================================================
    # 2. FEATURE VALUES
    # =========================================================

    hostname = features.get("hostname", "")
    base_domain = get_base_domain(hostname)

    is_trusted_domain = base_domain in TRUSTED_DOMAINS

    https = features.get("has_https", 0)
    has_ip = features.get("has_ip", 0)

    keyword_count = features.get("suspicious_word_count", 0)
    subdomains = features.get("num_subdomains", 0)

    punycode = features.get("has_punycode", 0)
    suspicious_tld = features.get("has_suspicious_tld", 0)

    encoded_count = features.get("num_encoded_chars", 0)

    has_at = features.get("has_at", 0)

    url_length = features.get("url_length", 0)
    hyphens = features.get("num_hyphens", 0)
    special_chars = features.get("num_special_chars", 0)

    entropy = features.get("url_entropy", 0)

    # =========================================================
    # 3. STRONG DOMAIN-LEVEL THREATS
    # =========================================================

    domain_level_threats = 0

    if has_ip:
        domain_level_threats += 1

    if punycode:
        domain_level_threats += 1

    if suspicious_tld:
        domain_level_threats += 1

    if has_at:
        domain_level_threats += 1

    # =========================================================
    # 4. SECURITY HEURISTICS
    # =========================================================

    adjustment = 0
    warning_signals = 0

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    if not https:
        adjustment += 6
        warning_signals += 1

    # ---------------------------------------------------------
    # IP ADDRESS
    # ---------------------------------------------------------

    if has_ip:
        adjustment += 18

    # ---------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # ---------------------------------------------------------

    if keyword_count > 0:
        keyword_points = min(keyword_count * 4, 16)

        adjustment += keyword_points
        warning_signals += 1

    # ---------------------------------------------------------
    # TOO MANY SUBDOMAINS
    # ---------------------------------------------------------

    if subdomains > 2:
        adjustment += 5
        warning_signals += 1

    # ---------------------------------------------------------
    # PUNYCODE
    # ---------------------------------------------------------

    if punycode:
        adjustment += 12

    # ---------------------------------------------------------
    # SUSPICIOUS TLD
    # ---------------------------------------------------------

    if suspicious_tld:
        adjustment += 7
        warning_signals += 1

    # ---------------------------------------------------------
    # ENCODED CHARACTERS
    # ---------------------------------------------------------

    # Encoding alone is NOT considered a major threat.
    if encoded_count > 2:
        adjustment += 3
        warning_signals += 1

    # ---------------------------------------------------------
    # @ SYMBOL
    # ---------------------------------------------------------

    if has_at:
        adjustment += 15

    # ---------------------------------------------------------
    # URL LENGTH
    # ---------------------------------------------------------

    # Long URLs receive only a small penalty.
    if url_length > 150:
        adjustment += 4
        warning_signals += 1

    elif url_length > 100:
        adjustment += 2
        warning_signals += 1

    # ---------------------------------------------------------
    # MANY HYPHENS
    # ---------------------------------------------------------

    if hyphens > 3:
        adjustment += 4
        warning_signals += 1

    # ---------------------------------------------------------
    # HIGH ENTROPY
    # ---------------------------------------------------------

    if entropy > 4.8:
        adjustment += 3
        warning_signals += 1

    # ---------------------------------------------------------
    # MANY SPECIAL CHARACTERS
    # ---------------------------------------------------------

    if special_chars > 4:
        adjustment += 3
        warning_signals += 1

    # =========================================================
    # 5. LIMIT HEURISTIC CONTRIBUTION
    # =========================================================

    # Weak indicators should never create Critical risk by
    # themselves.

    if domain_level_threats >= 2:
        adjustment = min(adjustment, 25)

    elif domain_level_threats == 1:
        adjustment = min(adjustment, 20)

    elif warning_signals >= 3:
        adjustment = min(adjustment, 12)

    else:
        adjustment = min(adjustment, 8)

    score += adjustment

    # =========================================================
    # 6. TRUSTED DOMAIN HANDLING
    # =========================================================

    if is_trusted_domain and domain_level_threats == 0:

        # Normal trusted website
        if keyword_count == 0 and warning_signals <= 1:
            score = min(score, 30)

        # Trusted domain but suspicious path
        elif keyword_count > 0:
            score = min(score, 55)
            score = max(score, 40)

        # Other minor warnings
        else:
            score = min(score, 40)

    # Trusted domain with a strong anomaly
    elif is_trusted_domain and domain_level_threats > 0:

        score = min(score, 70)

    # =========================================================
    # 7. STRONG PHISHING COMBINATIONS
    # =========================================================

    # These rules can override the normal score because they
    # represent combinations of genuinely strong indicators.

    if not is_trusted_domain or domain_level_threats > 0:

        # Many phishing keywords + no HTTPS
        if keyword_count >= 4 and not https:
            score = max(score, 85)

        # Many keywords + strong domain-level signal
        elif keyword_count >= 4 and domain_level_threats >= 1:
            score = max(score, 80)

        # Multiple keywords + no HTTPS
        elif keyword_count >= 2 and not https:
            score = max(score, 65)

        # IP + suspicious keywords
        if has_ip and keyword_count >= 1:
            score = max(score, 85)

        # @ + suspicious keywords
        if has_at and keyword_count >= 1:
            score = max(score, 85)

        # Punycode + suspicious keywords
        if punycode and keyword_count >= 1:
            score = max(score, 80)

    # =========================================================
    # 8. KEEP SCORE BETWEEN 0 AND 100
    # =========================================================

    score = max(0, min(100, score))

    # =========================================================
    # 9. RISK LEVEL
    # =========================================================

    if score >= 85:
        risk_level = "Critical"

    elif score >= 65:
        risk_level = "High"

    elif score >= 35:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    # =========================================================
    # 10. REASONS
    # =========================================================

    reasons = []

    if not https:
        reasons.append(
            "The URL does not use HTTPS."
        )

    if has_ip:
        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    if keyword_count > 0:
        reasons.append(
            "The URL contains words commonly associated with phishing."
        )

    if subdomains > 2:
        reasons.append(
            "The URL contains an unusually large number of subdomains."
        )

    if punycode:
        reasons.append(
            "The domain uses punycode, which can sometimes be used for lookalike domains."
        )

    if suspicious_tld:
        reasons.append(
            "The domain uses a potentially suspicious top-level domain."
        )

    if encoded_count > 2:
        reasons.append(
            "The URL contains several encoded characters."
        )

    if has_at:
        reasons.append(
            "The URL contains an @ symbol, which can hide the actual destination."
        )

    if url_length > 150:
        reasons.append(
            "The URL is unusually long."
        )

    elif url_length > 100:
        reasons.append(
            "The URL is somewhat long."
        )

    # ML explanation if there aren't obvious indicators
    if not reasons:

        if ml_probability >= 0.70:
            reasons.append(
                "The machine-learning model detected unusual URL patterns."
            )

        else:
            reasons.append(
                "No major suspicious URL indicators were detected."
            )

    # =========================================================
    # 11. DETECTION INDICATORS
    # =========================================================

    indicators = []

    # Trusted domain
    if is_trusted_domain:
        indicators.append({
            "name": "Trusted Domain",
            "status": "pass",
            "message": "Domain matches a commonly trusted website."
        })

    else:
        indicators.append({
            "name": "Domain",
            "status": "warning" if domain_level_threats > 0 else "pass",
            "message": "Domain does not match the trusted-domain list."
        })

    # HTTPS
    indicators.append({
        "name": "HTTPS",
        "status": "pass" if https else "warning",
        "message": (
            "Connection uses HTTPS."
            if https
            else "Connection does not use HTTPS."
        )
    })

    # IP
    indicators.append({
        "name": "IP Address",
        "status": "warning" if has_ip else "pass",
        "message": (
            "URL uses an IP address."
            if has_ip
            else "URL uses a normal domain."
        )
    })

    # Suspicious keywords
    indicators.append({
        "name": "Suspicious Keywords",
        "status": "warning" if keyword_count > 0 else "pass",
        "message": (
            f"{keyword_count} suspicious keyword(s) detected."
            if keyword_count > 0
            else "No suspicious keywords detected."
        )
    })

    # URL length
    indicators.append({
        "name": "URL Length",
        "status": "warning" if url_length > 150 else "pass",
        "message": f"URL contains {url_length} characters."
    })

    # =========================================================
    # 12. FINAL RESPONSE
    # =========================================================

    return {
        "threat_score": int(score),
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": indicators
    }