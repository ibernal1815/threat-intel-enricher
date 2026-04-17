import time
import requests
import config

# virustotal v3 API base — all lookups hit this
VT_BASE = "https://www.virustotal.com/api/v3"

# simple in-memory rate limiter state
# free tier is 4 requests/minute — we track timestamps and sleep when needed
_request_timestamps = []


def _rate_limit():
    """enforce the 4 req/min VT free tier limit.
    keeps a rolling window of the last 4 request timestamps and sleeps
    if we'd exceed the limit. not perfect for concurrent use but fine for a CLI."""
    global _request_timestamps

    now = time.time()
    window_start = now - config.VT_RATE_WINDOW

    # drop timestamps outside the current window
    _request_timestamps = [t for t in _request_timestamps if t > window_start]

    if len(_request_timestamps) >= config.VT_RATE_LIMIT:
        # oldest request in the window — sleep until it ages out
        sleep_until = _request_timestamps[0] + config.VT_RATE_WINDOW
        wait = sleep_until - now
        if wait > 0:
            print(f"[vt] rate limit reached, sleeping {wait:.1f}s...")
            time.sleep(wait)
        # prune again after sleeping
        now = time.time()
        _request_timestamps = [t for t in _request_timestamps if t > now - config.VT_RATE_WINDOW]

    _request_timestamps.append(time.time())


def _get(endpoint):
    """shared GET helper with auth header and basic error handling."""
    _rate_limit()
    headers = {"x-apikey": config.VT_API_KEY}
    try:
        resp = requests.get(f"{VT_BASE}{endpoint}", headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        print(f"[vt] HTTP {status} for {endpoint}")
        return {"error": f"http_{status}"}
    except requests.exceptions.RequestException as e:
        print(f"[vt] request failed: {e}")
        return {"error": "request_failed"}


def lookup_ip(ip):
    """query VT for an IP address. returns parsed result dict."""
    raw = _get(f"/ip_addresses/{ip}")
    return _parse_result(raw, ioc_type="ip")


def lookup_domain(domain):
    """query VT for a domain. returns parsed result dict."""
    raw = _get(f"/domains/{domain}")
    return _parse_result(raw, ioc_type="domain")


def lookup_hash(file_hash):
    """query VT for a file hash (md5, sha1, or sha256 — VT accepts all three)."""
    raw = _get(f"/files/{file_hash}")
    return _parse_result(raw, ioc_type="hash")


def _parse_result(raw, ioc_type):
    """extract the fields we actually care about from the VT response.
    keeps the raw response attached for --include-raw if needed."""

    if "error" in raw:
        return {
            "vt_error": raw["error"],
            "vt_detection_count": None,
            "vt_total_engines": None,
            "vt_tags": [],
            "vt_categories": [],
            "vt_last_analysis_stats": {},
            "vt_raw": raw,
        }

    data = raw.get("data", {})
    attrs = data.get("attributes", {})

    # last_analysis_stats gives us the breakdown: malicious, suspicious, clean, undetected
    stats = attrs.get("last_analysis_stats", {})
    detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    # tags and categories differ slightly between IPs, domains, and files
    tags = attrs.get("tags", [])

    # categories is a dict of {source: category} for IPs/domains, grab the values
    categories_raw = attrs.get("categories", {})
    if isinstance(categories_raw, dict):
        categories = list(set(categories_raw.values()))
    else:
        categories = categories_raw if isinstance(categories_raw, list) else []

    return {
        "vt_detection_count": detection_count,
        "vt_total_engines": total_engines,
        "vt_tags": tags,
        "vt_categories": categories,
        "vt_last_analysis_stats": stats,
        "vt_raw": raw,
    }
