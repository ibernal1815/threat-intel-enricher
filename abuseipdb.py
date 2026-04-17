import requests
import config

# abuseipdb v2 API — free tier covers 1000 checks/day
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

# abuse category codes from AbuseIPDB's documentation
# https://www.abuseipdb.com/categories
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute-Force",
    23: "IoT Targeted",
}


def lookup_ip(ip):
    """check an IP against AbuseIPDB. only IPs are supported — domains and hashes
    don't have an AbuseIPDB endpoint, so we skip those gracefully."""
    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": config.ABUSEIPDB_MAX_AGE_DAYS,
        "verbose": True,  # verbose gives us category codes on reports
    }

    try:
        resp = requests.get(
            f"{ABUSE_BASE}/check",
            headers=headers,
            params=params,
            timeout=15,
        )
        resp.raise_for_status()
        raw = resp.json()
        return _parse_result(raw)
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        print(f"[abuseipdb] HTTP {status} for {ip}")
        return {"abuse_error": f"http_{status}", "abuse_raw": {}}
    except requests.exceptions.RequestException as e:
        print(f"[abuseipdb] request failed: {e}")
        return {"abuse_error": "request_failed", "abuse_raw": {}}


def _parse_result(raw):
    """pull the fields we want out of the AbuseIPDB response."""

    data = raw.get("data", {})

    # confidence score: 0-100, higher = more confident this IP is malicious
    confidence = data.get("abuseConfidenceScore", 0)

    # total number of distinct reports in the lookback window
    total_reports = data.get("totalReports", 0)

    # collect unique category codes across all reports and map to names
    category_codes = set()
    for report in data.get("reports", []):
        for code in report.get("categories", []):
            category_codes.add(code)

    category_names = [
        ABUSE_CATEGORIES.get(code, f"unknown_category_{code}")
        for code in sorted(category_codes)
    ]

    # country and ISP are useful context for triage
    country = data.get("countryCode", "")
    isp = data.get("isp", "")
    usage_type = data.get("usageType", "")
    is_tor = data.get("isTor", False)

    return {
        "abuse_confidence_score": confidence,
        "abuse_total_reports": total_reports,
        "abuse_categories": category_names,
        "abuse_category_codes": sorted(list(category_codes)),
        "abuse_country": country,
        "abuse_isp": isp,
        "abuse_usage_type": usage_type,
        "abuse_is_tor": is_tor,
        "abuse_raw": raw,
    }
