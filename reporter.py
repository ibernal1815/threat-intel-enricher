import json
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich import box
import config

console = Console()

# verdict colors for rich markup
VERDICT_COLOR = {
    "malicious": "bold red",
    "suspicious": "bold yellow",
    "clean": "bold green",
}


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
        record["abuseipdb"] = "not_applicable"

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

    if metadata:
        report["metadata"] = metadata

    return report


def print_summary(report):
    """print a rich terminal summary of the enrichment report."""

    summary = report["summary"]
    by_verdict = summary["by_verdict"]
    total = summary["total_iocs"]

    console.print()
    console.print(f"[bold cyan]threat-intel-enricher[/bold cyan]  [dim]{report['generated_at']}[/dim]")
    console.print(f"[dim]enriched {total} IOC(s)[/dim]")
    console.print()

    # verdict summary line
    parts = []
    for verdict, count in by_verdict.items():
        if count:
            color = VERDICT_COLOR.get(verdict, "white")
            parts.append(f"[{color}]{count} {verdict}[/{color}]")
    if parts:
        console.print("  " + "  ·  ".join(parts))
    console.print()

    # one row per IOC
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    table.add_column("IOC", style="cyan", no_wrap=True)
    table.add_column("type", style="dim")
    table.add_column("verdict")
    table.add_column("VT", justify="right")
    table.add_column("abuse score", justify="right")
    table.add_column("tags")

    for rec in report["iocs"]:
        verdict = rec.get("verdict", "clean")
        color = VERDICT_COLOR.get(verdict, "white")
        verdict_str = f"[{color}]{verdict}[/{color}]"

        vt = rec.get("virustotal", {})
        det = vt.get("detection_count")
        total_eng = vt.get("total_engines")
        vt_str = f"{det}/{total_eng}" if det is not None and total_eng else "n/a"

        abuse = rec.get("abuseipdb")
        if isinstance(abuse, dict):
            score = abuse.get("confidence_score")
            is_tor = abuse.get("is_tor")
            abuse_str = f"{score}%" if score is not None else "n/a"
            if is_tor:
                abuse_str += " [dim](tor)[/dim]"
        else:
            abuse_str = "n/a"

        tags = ", ".join(vt.get("tags", [])[:3]) or "—"

        table.add_row(rec["ioc"], rec["type"], verdict_str, vt_str, abuse_str, tags)

    console.print(table)


def output_report(report, output_file=None, pretty=True):
    """print rich summary to stderr, then write JSON to stdout or file."""

    # always print the terminal summary
    print_summary(report)

    indent = 2 if pretty else None
    serialized = json.dumps(report, indent=indent, default=str)

    if output_file:
        with open(output_file, "w") as f:
            f.write(serialized)
        console.print(f"[dim]report saved to {output_file}[/dim]", stderr=True)
    else:
        print(serialized)