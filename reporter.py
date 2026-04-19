import json
import sys
from datetime import datetime, timezone
import config


def determine_verdict(ioc_type, vt_data, abuse_data=None):
    """compute a verdict based on detection counts and confidence scores.

    verdict levels: clean / suspicious / malicious
    logic: if either VT or AbuseIPDB crosses the malicious threshold, it's malicious.
    if either crosses suspicious (but not malicious), it's suspicious.
    otherwise clean.

    having any one source flag something as malicious is enough — in a SOC context
    you'd rather investigate a false positive than miss a true positive."""

    malicious = False
    suspicious = False

    # vt detection count check
    vt_count = vt_data.get("vt_detection_count")
    if vt_count is not None:
        if vt_count >= config.VT_MALICIOUS_THRESHOLD:
            malicious = True
        elif vt_count >= config.VT_SUSPICIOUS_THRESHOLD:
            suspicious = True

    # abuseipdb only applies to IPs
    if ioc_type == "ip" and abuse_data:
        abuse_score = abuse_data.get("abuse_confidence_score", 0)
        if abuse_score >= config.ABUSE_MALICIOUS_THRESHOLD:
            malicious = True
        elif abuse_score >= config.ABUSE_SUSPICIOUS_THRESHOLD:
            suspicious = True

        # tor exit nodes are suspicious by default regardless of score
        if abuse_data.get("abuse_is_tor"):
            suspicious = True

    if malicious:
        return "malicious"
    if suspicious:
        return "suspicious"
    return "clean"


def build_ioc_record(ioc_value, ioc_type, vt_data, abuse_data=None, include_raw=False):
    """assemble a single IOC's enriched record. this is the core output unit."""

    verdict = determine_verdict(ioc_type, vt_data, abuse_data)

    record = {
        "ioc": ioc_value,
        "type": ioc_type,
        "verdict": verdict,
        "virustotal": {
            "detection_count": vt_data.get("vt_detection_count"),
            "total_engines": vt_data.get("vt_total_engines"),
            "tags": vt_data.get("vt_tags", []),
            "categories": vt_data.get("vt_categories", []),
            "analysis_stats": vt_data.get("vt_last_analysis_stats", {}),
        },
    }

    # vt errors — show them so you know a lookup failed rather than silently getting clean
    if "vt_error" in vt_data:
        record["virustotal"]["error"] = vt_data["vt_error"]

    # abuseipdb only for IPs
    if ioc_type == "ip":
        if abuse_data:
            record["abuseipdb"] = {
                "confidence_score": abuse_data.get("abuse_confidence_score"),
                "total_reports": abuse_data.get("abuse_total_reports"),
                "categories": abuse_data.get("abuse_categories", []),
                "country": abuse_data.get("abuse_country"),
                "isp": abuse_data.get("abuse_isp"),
                "usage_type": abuse_data.get("abuse_usage_type"),
                "is_tor": abuse_data.get("abuse_is_tor"),
            }
            if "abuse_error" in abuse_data:
                record["abuseipdb"]["error"] = abuse_data["abuse_error"]
        else:
            record["abuseipdb"] = None
    else:
        # domains and hashes: note that abuseipdb doesn't support them
        record["abuseipdb"] = "not_applicable"

    # raw responses are large — only include them if explicitly requested
    if include_raw:
        record["_raw"] = {
            "virustotal": vt_data.get("vt_raw"),
        }
        if ioc_type == "ip" and abuse_data:
            record["_raw"]["abuseipdb"] = abuse_data.get("abuse_raw")

    return record


def build_report(ioc_records, metadata=None):
    """wrap enriched IOC records in a report envelope with summary stats."""

    total = len(ioc_records)
    by_verdict = {"clean": 0, "suspicious": 0, "malicious": 0}
    by_type = {"ip": 0, "domain": 0, "hash": 0}

    for rec in ioc_records:
        verdict = rec.get("verdict", "clean")
        ioc_type = rec.get("type", "unknown")
        if verdict in by_verdict:
            by_verdict[verdict] += 1
        if ioc_type in by_type:
            by_type[ioc_type] += 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_iocs": total,
            "by_verdict": by_verdict,
            "by_type": by_type,
        },
        "iocs": ioc_records,
    }

    # attach any extra metadata passed in (e.g. source file, pipeline info)
    if metadata:
        report["metadata"] = metadata

    return report


def output_report(report, output_file=None, pretty=True):
    """write the report to stdout or a file."""
    indent = 2 if pretty else None
    serialized = json.dumps(report, indent=indent, default=str)

    if output_file:
        with open(output_file, "w") as f:
            f.write(serialized)
        print(f"[reporter] wrote report to {output_file}", file=sys.stderr)
    else:
        print(serialized)
