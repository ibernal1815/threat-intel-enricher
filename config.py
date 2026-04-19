import os
import sys

# all API keys come from environment variables — never hardcoded, never committed
# set them before running:
#   export VT_API_KEY="your_key_here"
#   export ABUSEIPDB_API_KEY="your_key_here"

VT_API_KEY = os.environ.get("VT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

# virustotal free tier: 4 requests/minute, 500/day
VT_RATE_LIMIT = 4        # requests per minute
VT_RATE_WINDOW = 60      # seconds

# verdict thresholds — tune these to your environment
# VT: number of engines flagging something as malicious
VT_SUSPICIOUS_THRESHOLD = 3
VT_MALICIOUS_THRESHOLD = 10

# AbuseIPDB: confidence score out of 100
ABUSE_SUSPICIOUS_THRESHOLD = 25
ABUSE_MALICIOUS_THRESHOLD = 75

# AbuseIPDB max age in days for report lookback
ABUSEIPDB_MAX_AGE_DAYS = 90


def validate_keys(require_vt=True, require_abuse=True):
    """check that the needed API keys are present before making requests.
    call this early so you get a clear error instead of a 401 buried in a traceback."""
    missing = []

    if require_vt and not VT_API_KEY:
        missing.append("VT_API_KEY")
    if require_abuse and not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")

    if missing:
        print(f"[error] missing required env vars: {', '.join(missing)}", file=sys.stderr)
        print("[error] set them with: export VAR_NAME='your_key'", file=sys.stderr)
        sys.exit(1)
