# threat-intel-enricher

takes IOCs (IPs, domains, file hashes) and enriches them against VirusTotal and AbuseIPDB. outputs a structured JSON report with detection counts, abuse confidence scores, tags, and a verdict per IOC.

built to work as a pipeline with [log-normalizer](https://github.com/yourusername/log-normalizer), but works fine standalone too.

## setup

```bash
git clone https://github.com/yourusername/threat-intel-enricher
cd threat-intel-enricher
pip install requests
```

set your API keys as environment variables before running. free keys at [virustotal.com](https://www.virustotal.com) and [abuseipdb.com](https://www.abuseipdb.com).

```bash
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

VT free tier is 4 requests/minute and 500/day. the rate limiter handles the per-minute cap automatically.

## usage

pipe from log-normalizer:

```bash
python main.py --input auth.log --iocs-only | python enricher.py
```

load from a JSON file:

```bash
python enricher.py --iocs iocs.json
```

pass IOCs directly:

```bash
python enricher.py --ip 185.220.101.5 --domain malicious.example.com --hash abc123...
```

enrich inline with full log-normalizer output:

```bash
python main.py --input auth.log | python enricher.py --enrich
```

write to a file instead of stdout:

```bash
python enricher.py --iocs iocs.json --output report.json
```

include raw API responses (useful for debugging or deeper triage):

```bash
python enricher.py --ip 185.220.101.5 --include-raw
```

compact output for piping into jq or other tools:

```bash
python enricher.py --iocs iocs.json --compact | jq '.iocs[] | select(.verdict == "malicious")'
```

## output

each IOC gets a record like this:

```json
{
  "ioc": "185.220.101.5",
  "type": "ip",
  "verdict": "malicious",
  "virustotal": {
    "detection_count": 17,
    "total_engines": 93,
    "tags": ["tor-exit-node", "scanner"],
    "categories": ["malicious sites"],
    "analysis_stats": {
      "malicious": 15,
      "suspicious": 2,
      "undetected": 10,
      "harmless": 5,
      "timeout": 0
    }
  },
  "abuseipdb": {
    "confidence_score": 95,
    "total_reports": 142,
    "categories": ["Brute-Force", "SSH Brute-Force", "Port Scan", "Hacking"],
    "country": "NL",
    "isp": "Frantech Solutions",
    "usage_type": "Data Center/Web Hosting/Transit",
    "is_tor": true
  }
}
```

the full report wraps all IOCs in a summary envelope with counts by verdict and type.

verdicts are `clean`, `suspicious`, or `malicious`. the thresholds are in `config.py` and tunable. defaults are 10 VT engines for malicious and 75 AbuseIPDB confidence score. Tor exit nodes get flagged suspicious regardless of score.

## tests

all API calls are mocked so you don't need real keys to run the suite:

```bash
python -m pytest tests/ -v
```

## related projects

[log-normalizer](https://github.com/yourusername/log-normalizer) extracts and normalizes IOCs from raw security logs. the `--iocs-only` flag pipes directly into this tool.
