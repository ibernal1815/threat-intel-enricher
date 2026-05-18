# threat-intel-enricher

Takes IOCs (IPs, domains, file hashes) and enriches them against VirusTotal and AbuseIPDB. Outputs a structured JSON report with detection counts, abuse confidence scores, tags, and a verdict per IOC.

Built to work as a pipeline with [log-normalizer](https://github.com/ibernal1815/log-normalizer), but works fine standalone too.

## Background

Extracting IOCs from logs is only half the work. The other half is knowing whether those IOCs are actually malicious. I built this to close that gap — once log-normalizer pulls IPs, domains, and hashes out of a log file, this tool runs them through VirusTotal and AbuseIPDB and comes back with a verdict.

The rate limiter handles the VT free tier cap automatically so you can enrich a full IOC set without babysitting the requests.

## Setup

```bash
git clone https://github.com/ibernal1815/threat-intel-enricher
cd threat-intel-enricher
pip install -r requirements.txt
```

Set your API keys as environment variables before running. Free keys at [virustotal.com](https://www.virustotal.com) and [abuseipdb.com](https://www.abuseipdb.com).

```bash
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

VT free tier is 4 requests/minute and 500/day. The rate limiter handles the per-minute cap automatically.

## Usage

Pipe from log-normalizer:

```bash
python main.py --input auth.log --iocs-only | python enricher.py
```

Load from a JSON file:

```bash
python enricher.py --iocs iocs.json
```

Pass IOCs directly:

```bash
python enricher.py --ip 185.220.101.5 --domain malicious.example.com --hash abc123...
```

Enrich inline with full log-normalizer output:

```bash
python main.py --input auth.log | python enricher.py --enrich
```

Write to a file instead of stdout:

```bash
python enricher.py --iocs iocs.json --output report.json
```

Include raw API responses (useful for debugging or deeper triage):

```bash
python enricher.py --ip 185.220.101.5 --include-raw
```

Compact output for piping into jq or other tools:

```bash
python enricher.py --iocs iocs.json --compact | jq '.iocs[] | select(.verdict == "malicious")'
```

## Output

Each IOC gets a record like this:

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

The full report wraps all IOCs in a summary envelope with counts by verdict and type.

Verdicts are `clean`, `suspicious`, or `malicious`. The thresholds are in `config.py` and tunable. Defaults are 10 VT engines for malicious and 75 AbuseIPDB confidence score. Tor exit nodes get flagged suspicious regardless of score.

## Tests

All API calls are mocked so you do not need real keys to run the suite:

```bash
python -m pytest test_enricher.py -v
```

## Related Projects

[log-normalizer](https://github.com/ibernal1815/log-normalizer) parses and normalizes raw security logs into structured JSON. The `--iocs-only` flag pipes directly into this tool.

## Stack

Python 3 · requests · rich · pytest
