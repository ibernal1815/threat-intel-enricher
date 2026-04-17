#!/usr/bin/env python3
"""
threat-intel-enricher
takes IOCs (IPs, domains, file hashes) and enriches them against
VirusTotal and AbuseIPDB, then outputs a structured JSON report.

works standalone or as part of a pipeline with log-normalizer:
    python main.py --input auth.log --iocs-only | python enricher.py
"""

import sys
import json
import argparse
import re

import config
import vt
import abuseipdb
import reporter


# regex patterns for IOC type detection
# these are intentionally simple — if you need strict validation, tighten them
IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
# md5, sha1, or sha256 — covers the common cases
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def detect_ioc_type(value):
    """figure out what kind of IOC we're looking at based on its format.
    returns 'ip', 'domain', 'hash', or None if it doesn't match anything."""
    value = value.strip()
    if IP_PATTERN.match(value):
        return "ip"
    if HASH_PATTERN.match(value):
        return "hash"
    if DOMAIN_PATTERN.match(value):
        return "domain"
    return None


def parse_ioc_input(ioc_list):
    """normalize a list of raw IOC strings into typed dicts.
    skips anything that doesn't look like a recognizable IOC type."""
    typed = []
    skipped = []

    for raw in ioc_list:
        raw = raw.strip()
        if not raw:
            continue
        ioc_type = detect_ioc_type(raw)
        if ioc_type:
            typed.append({"value": raw, "type": ioc_type})
        else:
            skipped.append(raw)

    if skipped:
        print(f"[enricher] skipped {len(skipped)} unrecognized IOC(s): {skipped[:5]}", file=sys.stderr)

    return typed


def load_iocs_from_file(path):
    """load IOCs from a JSON file. supports both formats:
    - flat list of strings: ["1.2.3.4", "malware.com"]
    - log-normalizer output: {"iocs": [...]} or {"results": [{"iocs": [...]}]}
    """
    with open(path) as f:
        data = json.load(f)

    # flat list of strings
    if isinstance(data, list) and all(isinstance(i, str) for i in data):
        return data

    # log-normalizer --iocs-only format: {"iocs": [...]}
    if isinstance(data, dict) and "iocs" in data:
        return data["iocs"]

    # log-normalizer full output: {"results": [{"iocs": [...]}]}
    if isinstance(data, dict) and "results" in data:
        iocs = []
        for entry in data["results"]:
            iocs.extend(entry.get("iocs", []))
        return iocs

    # list of objects with a "value" key: [{"value": "1.2.3.4", ...}]
    if isinstance(data, list) and all(isinstance(i, dict) for i in data):
        return [i["value"] for i in data if "value" in i]

    print("[enricher] couldn't parse iocs from file — unexpected format", file=sys.stderr)
    sys.exit(1)


def load_iocs_from_stdin():
    """read JSON from stdin — used when piped from log-normalizer.
    expects the same formats as load_iocs_from_file."""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"[enricher] failed to parse stdin as JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # reuse file loader logic by writing to a temp dict
    if isinstance(data, dict) and "iocs" in data:
        return data["iocs"]
    if isinstance(data, dict) and "results" in data:
        iocs = []
        for entry in data["results"]:
            iocs.extend(entry.get("iocs", []))
        return iocs
    if isinstance(data, list):
        return data

    print("[enricher] couldn't parse iocs from stdin", file=sys.stderr)
    sys.exit(1)


def enrich_ioc(ioc, include_raw=False):
    """run a single IOC through VT and (if IP) AbuseIPDB.
    returns a fully assembled record from reporter.build_ioc_record."""
    value = ioc["value"]
    ioc_type = ioc["type"]

    print(f"[enricher] enriching {ioc_type}: {value}", file=sys.stderr)

    # VT lookup — all types go through VT
    if ioc_type == "ip":
        vt_data = vt.lookup_ip(value)
    elif ioc_type == "domain":
        vt_data = vt.lookup_domain(value)
    elif ioc_type == "hash":
        vt_data = vt.lookup_hash(value)
    else:
        vt_data = {"vt_error": "unsupported_type"}

    # AbuseIPDB — IPs only
    abuse_data = None
    if ioc_type == "ip":
        abuse_data = abuseipdb.lookup_ip(value)

    return reporter.build_ioc_record(value, ioc_type, vt_data, abuse_data, include_raw)


def main():
    parser = argparse.ArgumentParser(
        description="enrich IOCs against VirusTotal and AbuseIPDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # pipe from log-normalizer
  python main.py --input auth.log --iocs-only | python enricher.py

  # load from file
  python enricher.py --iocs iocs.json

  # pass IOCs directly
  python enricher.py --ip 185.220.101.5 --domain evil.example.com

  # add to log-normalizer output directly
  python main.py --input auth.log | python enricher.py --enrich
        """,
    )

    # input sources — pick one
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--iocs", metavar="FILE", help="JSON file containing IOCs")
    input_group.add_argument(
        "--enrich",
        action="store_true",
        help="read full log-normalizer JSON from stdin and enrich its IOCs inline",
    )

    # direct IOC flags — can be combined and used alongside --iocs
    parser.add_argument("--ip", metavar="ADDR", action="append", default=[], help="IP address to enrich")
    parser.add_argument("--domain", metavar="DOMAIN", action="append", default=[], help="domain to enrich")
    parser.add_argument("--hash", metavar="HASH", action="append", default=[], dest="hashes", help="file hash to enrich")

    # output options
    parser.add_argument("--output", metavar="FILE", help="write JSON report to file instead of stdout")
    parser.add_argument("--include-raw", action="store_true", help="include full raw API responses in output")
    parser.add_argument("--compact", action="store_true", help="compact JSON output (no indentation)")

    args = parser.parse_args()

    # collect all IOC strings
    raw_iocs = []

    # stdin pipe (no --iocs flag, no explicit IOCs, and stdin isn't a tty)
    stdin_is_pipe = not sys.stdin.isatty()

    if args.enrich and stdin_is_pipe:
        # --enrich mode: read log-normalizer output, extract and enrich IOCs
        raw_iocs.extend(load_iocs_from_stdin())
    elif stdin_is_pipe and not args.iocs and not args.ip and not args.domain and not args.hashes:
        # piped input without --enrich: treat stdin as iocs-only output
        raw_iocs.extend(load_iocs_from_stdin())

    if args.iocs:
        raw_iocs.extend(load_iocs_from_file(args.iocs))

    # direct CLI flags
    raw_iocs.extend(args.ip)
    raw_iocs.extend(args.domain)
    raw_iocs.extend(args.hashes)

    if not raw_iocs:
        parser.print_help()
        sys.exit(0)

    # validate API keys before doing any work
    # check which keys we actually need based on IOC types
    typed_iocs = parse_ioc_input(raw_iocs)
    has_ip = any(i["type"] == "ip" for i in typed_iocs)
    has_non_ip = any(i["type"] != "ip" for i in typed_iocs)

    # VT is always needed; AbuseIPDB only needed if we have IPs
    config.validate_keys(require_vt=True, require_abuse=has_ip)

    if not typed_iocs:
        print("[enricher] no valid IOCs found, nothing to enrich", file=sys.stderr)
        sys.exit(0)

    print(f"[enricher] enriching {len(typed_iocs)} IOC(s)...", file=sys.stderr)

    # run enrichment
    records = [enrich_ioc(ioc, include_raw=args.include_raw) for ioc in typed_iocs]

    # build and output report
    report = reporter.build_report(records)
    reporter.output_report(report, output_file=args.output, pretty=not args.compact)


if __name__ == "__main__":
    main()
