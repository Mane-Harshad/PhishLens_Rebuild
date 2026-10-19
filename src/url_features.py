
import ipaddress
import re
from urllib.parse import urlsplit

import pandas as pd


SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure",
    "account", "password", "signin", "banking",
    "update", "confirm", "wallet", "recover",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly",
}

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "hyphen_count",
    "at_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "uses_https",
    "has_ip_host",
    "has_port",
    "has_query",
    "has_fragment",
    "has_suspicious_keyword",
    "uses_shortener",
]


def extract_url_features(url):
    """Convert a raw URL into numerical features without visiting it."""

    raw_url = str(url).strip()
    lowered = raw_url.lower()

    # Parse URLs with or without an explicit scheme.
    candidate = raw_url if "://" in raw_url else "//" + raw_url

    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
    except ValueError:
        hostname = ""
        path = ""
        query = ""
        fragment = ""

    hostname = hostname.rstrip(".")

    # Count IP-address hosts safely.
    try:
        ipaddress.ip_address(hostname)
        has_ip_host = 1
    except ValueError:
        has_ip_host = 0

    # Approximate subdomains using hostname labels.
    # This is a simple heuristic, not a public-suffix lookup.
    labels = [part for part in hostname.split(".") if part]
    subdomain_count = max(0, len(labels) - 2)

    digit_count = sum(char.isdigit() for char in raw_url)
    special_chars = sum(
        not char.isalnum() for char in raw_url
    )

    hostname_labels = set(labels)
    uses_shortener = int(
        hostname in SHORTENER_DOMAINS
        or any(
            hostname.endswith("." + domain)
            for domain in SHORTENER_DOMAINS
        )
    )

    return {
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": hostname.count("."),
        "subdomain_count": subdomain_count,
        "hyphen_count": hostname.count("-"),
        "at_count": raw_url.count("@"),
        "digit_count": digit_count,
        "digit_ratio": digit_count / max(1, len(raw_url)),
        "special_char_count": special_chars,
        "uses_https": int(lowered.startswith("https://")),
        "has_ip_host": has_ip_host,
        "has_port": int(parsed_port_present(raw_url)),
        "has_query": int(bool(query)),
        "has_fragment": int(bool(fragment)),
        "has_suspicious_keyword": int(
            any(
                keyword in lowered
                for keyword in SUSPICIOUS_KEYWORDS
            )
        ),
        "uses_shortener": uses_shortener,
    }


def parsed_port_present(url):
    candidate = url if "://" in url else "//" + url

    try:
        return urlsplit(candidate).port is not None
    except ValueError:
        return False


def extract_features_dataframe(urls):
    """Return a feature matrix with consistent column order."""

    rows = [extract_url_features(url) for url in urls]

    return pd.DataFrame(
        rows,
        columns=FEATURE_COLUMNS,
    )
