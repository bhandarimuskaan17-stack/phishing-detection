
from urllib.parse import urlparse
import ipaddress
import math
from collections import Counter


def normalize_url(url):
    """
    Make user-entered URLs easier to analyze.

    Examples:
        google.com
        http://google.com
        https://google.com
    """

    url = url.strip()

    if not url:
        return ""

    # If the user did not specify a scheme,
    # assume HTTPS for analysis.
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    return url


def calculate_entropy(text):
    """
    Calculate Shannon entropy.
    Higher values can indicate more random/obfuscated text.
    """

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(url):
    """
    Extract security-related features from a URL.
    """

    # Normalize URL first
    url = normalize_url(url)

    parsed_url = urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    url_lower = url.lower()
    hostname_lower = hostname.lower()

    # --------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------

    try:

        ipaddress.ip_address(hostname)

        has_ip = 1

    except (ValueError, TypeError):

        has_ip = 0

    # --------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------

    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "password",
        "bank",
        "payment",
        "confirm",
        "wallet",
        "billing",
        "recover",
        "unlock",
        "authenticate"
    ]

    suspicious_word_count = sum(
        word in url_lower
        for word in suspicious_words
    )

    # --------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------

    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".click",
        ".download",
        ".work",
        ".zip"
    ]

    has_suspicious_tld = int(
        any(
            hostname_lower.endswith(tld)
            for tld in suspicious_tlds
        )
    )

    # --------------------------------------------------
    # ENCODING
    # --------------------------------------------------

    num_encoded_chars = url_lower.count("%")

    # --------------------------------------------------
    # DOUBLE SLASH IN PATH
    # --------------------------------------------------

    has_double_slash = int("//" in path)

    # --------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------

    num_subdomains = max(
        0,
        hostname.count(".") - 1
    )

    # --------------------------------------------------
    # ENTROPY
    # --------------------------------------------------

    url_entropy = calculate_entropy(url)

    # --------------------------------------------------
    # FEATURES
    # --------------------------------------------------

    features = {

        "hostname": hostname,

        "url_length": len(url),

        "domain_length": len(hostname),

        "path_length": len(path),

        "query_length": len(query),

        "has_https": int(
            parsed_url.scheme.lower() == "https"
        ),

        "has_ip": has_ip,

        "num_dots": url.count("."),

        "num_hyphens": url.count("-"),

        "num_slashes": url.count("/"),

        "num_digits": sum(
            char.isdigit()
            for char in url
        ),

        "num_letters": sum(
            char.isalpha()
            for char in url
        ),

        "num_special_chars": sum(
            1
            for char in url
            if char in "@?=&%"
        ),

        "has_at": int(
            "@" in url
        ),

        "has_question": int(
            "?" in url
        ),

        "has_equals": int(
            "=" in url
        ),

        "has_ampersand": int(
            "&" in url
        ),

        "has_percent": int(
            "%" in url
        ),

        "num_subdomains": num_subdomains,

        "has_punycode": int(
            "xn--" in hostname_lower
        ),

        "suspicious_word_count":
            suspicious_word_count,

        "has_suspicious_tld":
            has_suspicious_tld,

        "num_encoded_chars":
            num_encoded_chars,

        "has_double_slash":
            has_double_slash,

        "url_entropy":
            round(url_entropy, 4),

        "has_fragment":
            int(bool(parsed_url.fragment)),

        "num_colons":
            url.count(":"),

        "num_semicolons":
            url.count(";"),

        "num_underscores":
            url.count("_"),

        "num_parentheses":
            url.count("(") + url.count(")")
    }

    return features
