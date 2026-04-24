"""
=============================================================
  IOC Threat Intelligence Module
  --------------------------------
  A Python CLI tool that queries public threat intelligence
  APIs to enrich Indicators of Compromise (IOCs) such as:
    - IP addresses
    - Domain names
    - File hashes (MD5, SHA1, SHA256)

  APIs Used:
    - VirusTotal  (https://www.virustotal.com)
    - AbuseIPDB   (https://www.abuseipdb.com)

  Output:
    - Rich formatted CLI report
    - JSON log file (SIEM-ingestible)
=============================================================
"""

import re
import sys
import json
import datetime
import argparse
import requests
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

# ─────────────────────────────────────────────
#  CONFIGURATION
#  Replace these with actual API keys.
# ─────────────────────────────────────────────
VIRUSTOTAL_API_KEY = "VIRUSTOTAL_KEY"
ABUSEIPDB_API_KEY  = "ABUSEIPDB_KEY"

# Output log directory
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Rich console for pretty CLI output
console = Console()


# ─────────────────────────────────────────────
#  HELPER: Detect IOC Type
# ─────────────────────────────────────────────
def detect_ioc_type(ioc: str) -> str:
    """
    Automatically detects whether the input is an:
      - IP address
      - Domain name
      - File hash (MD5 / SHA1 / SHA256)
    Returns a string label for the type.
    """
    # IPv4 pattern
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    # Hash patterns by length
    hash_lengths = {32: "md5", 40: "sha1", 64: "sha256"}
    # Domain pattern (basic)
    domain_pattern = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    if ip_pattern.match(ioc):
        return "ip"
    elif len(ioc) in hash_lengths and re.match(r"^[a-fA-F0-9]+$", ioc):
        return hash_lengths[len(ioc)]
    elif domain_pattern.match(ioc):
        return "domain"
    else:
        return "unknown"


# ─────────────────────────────────────────────
#  API QUERY: VirusTotal
# ─────────────────────────────────────────────
def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Queries the VirusTotal API v3 to get threat intelligence
    about an IP, domain, or file hash.

    Returns a dictionary of enriched data or an error message.
    """
    base_url = "https://www.virustotal.com/api/v3"
    headers  = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Choose the correct endpoint based on IOC type
    if ioc_type == "ip":
        url = f"{base_url}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{base_url}/domains/{ioc}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        url = f"{base_url}/files/{ioc}"
    else:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        # Handle API errors gracefully
        if response.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        if response.status_code == 404:
            return {"error": "IOC not found in VirusTotal database"}
        if response.status_code != 200:
            return {"error": f"VirusTotal API error: HTTP {response.status_code}"}

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})

        # Extract the last_analysis_stats block
        # This shows how many AV engines flagged this IOC
        stats = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Build a clean result dictionary
        result = {
            "source":     "VirusTotal",
            "ioc":        ioc,
            "ioc_type":   ioc_type,
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "total_engines": total,
            "reputation": attrs.get("reputation", "N/A"),
        }

        # Add extra fields depending on IOC type
        if ioc_type == "ip":
            result["country"]  = attrs.get("country", "N/A")
            result["owner"]    = attrs.get("as_owner", "N/A")
            result["asn"]      = attrs.get("asn", "N/A")

        elif ioc_type == "domain":
            result["registrar"]   = attrs.get("registrar", "N/A")
            result["creation_date"] = attrs.get("creation_date", "N/A")

        elif ioc_type in ("md5", "sha1", "sha256"):
            result["file_name"]   = attrs.get("meaningful_name", "N/A")
            result["file_type"]   = attrs.get("type_description", "N/A")
            result["file_size"]   = attrs.get("size", "N/A")
            result["tags"]        = attrs.get("tags", [])

        return result

    except requests.exceptions.ConnectionError:
        return {"error": "Network error — could not reach VirusTotal"}
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out"}


# ─────────────────────────────────────────────
#  API QUERY: AbuseIPDB (IP addresses only)
# ─────────────────────────────────────────────
def query_abuseipdb(ip: str) -> dict:
    """
    Queries AbuseIPDB for abuse reports on an IP address.
    Returns confidence score, country, ISP, and report count.
    Only applicable to IP addresses.
    """
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key"}
        if response.status_code != 200:
            return {"error": f"AbuseIPDB API error: HTTP {response.status_code}"}

        data = response.json().get("data", {})

        return {
            "source":            "AbuseIPDB",
            "ioc":               ip,
            "ioc_type":          "ip",
            "abuse_confidence":  data.get("abuseConfidenceScore", 0),
            "country":           data.get("countryCode", "N/A"),
            "isp":               data.get("isp", "N/A"),
            "domain":            data.get("domain", "N/A"),
            "total_reports":     data.get("totalReports", 0),
            "last_reported":     data.get("lastReportedAt", "Never"),
            "is_whitelisted":    data.get("isWhitelisted", False),
            "usage_type":        data.get("usageType", "N/A"),
        }

    except requests.exceptions.ConnectionError:
        return {"error": "Network error — could not reach AbuseIPDB"}
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB request timed out"}


# ─────────────────────────────────────────────
#  SCORING: Calculate Threat Level
# ─────────────────────────────────────────────
def calculate_threat_level(vt_result: dict, abuse_result: dict = None) -> tuple:
    """
    Combines results from multiple APIs into a single
    threat score and severity label.

    Scoring logic:
      - VirusTotal malicious detections contribute heavily
      - AbuseIPDB confidence score adds to the score
      - Final score mapped to: LOW / MEDIUM / HIGH / CRITICAL
    """
    score = 0

    # VirusTotal scoring
    if "malicious" in vt_result:
        malicious = vt_result["malicious"]
        total     = vt_result.get("total_engines", 1) or 1
        vt_ratio  = malicious / total

        if malicious > 0:
            score += 30                    # Base penalty for any detection
            score += min(vt_ratio * 50, 50) # Up to 50 more based on ratio

    # AbuseIPDB scoring
    if abuse_result and "abuse_confidence" in abuse_result:
        confidence = abuse_result["abuse_confidence"]
        score += confidence * 0.2          # Max +20 from AbuseIPDB

    # Cap at 100
    score = min(score, 100)

    # Map score to severity label
    if score >= 75:
        level = "CRITICAL"
        color = "red"
    elif score >= 50:
        level = "HIGH"
        color = "orange1"
    elif score >= 25:
        level = "MEDIUM"
        color = "yellow"
    else:
        level = "LOW"
        color = "green"

    return round(score, 1), level, color


# ─────────────────────────────────────────────
#  OUTPUT: Print Rich CLI Report
# ─────────────────────────────────────────────
def print_report(ioc: str, ioc_type: str, vt: dict, abuse: dict, score: float, level: str, color: str):
    """
    Prints a formatted threat intelligence report to the terminal
    using the Rich library for colour and styling.
    """
    console.print()
    console.print(Panel(
        f"[bold]IOC:[/bold] {ioc}   [bold]Type:[/bold] {ioc_type.upper()}   "
        f"[bold]Threat Level:[/bold] [{color}]{level}[/{color}]   "
        f"[bold]Score:[/bold] {score}/100",
        title="[bold cyan]🛡  IOC THREAT INTELLIGENCE REPORT[/bold cyan]",
        border_style="cyan"
    ))

    # ── VirusTotal Results ──────────────────────
    if "error" in vt:
        console.print(f"[red]VirusTotal Error:[/red] {vt['error']}")
    else:
        vt_table = Table(title="VirusTotal Analysis", box=box.ROUNDED, border_style="blue")
        vt_table.add_column("Field", style="bold")
        vt_table.add_column("Value")

        vt_table.add_row("Malicious Detections",
            f"[red]{vt['malicious']}[/red] / {vt['total_engines']} engines")
        vt_table.add_row("Suspicious",  str(vt.get("suspicious", "N/A")))
        vt_table.add_row("Harmless",    str(vt.get("harmless",   "N/A")))
        vt_table.add_row("Reputation",  str(vt.get("reputation", "N/A")))

        # Add type-specific fields
        for field in ["country", "owner", "asn", "registrar",
                      "file_name", "file_type", "file_size"]:
            if field in vt:
                vt_table.add_row(field.replace("_", " ").title(), str(vt[field]))

        console.print(vt_table)

    # ── AbuseIPDB Results (IP only) ─────────────
    if abuse:
        if "error" in abuse:
            console.print(f"[red]AbuseIPDB Error:[/red] {abuse['error']}")
        else:
            ab_table = Table(title="AbuseIPDB Report", box=box.ROUNDED, border_style="magenta")
            ab_table.add_column("Field", style="bold")
            ab_table.add_column("Value")

            confidence = abuse['abuse_confidence']
            conf_color = "red" if confidence > 75 else "yellow" if confidence > 25 else "green"

            ab_table.add_row("Abuse Confidence",
                f"[{conf_color}]{confidence}%[/{conf_color}]")
            ab_table.add_row("Total Reports",   str(abuse["total_reports"]))
            ab_table.add_row("Country",         abuse["country"])
            ab_table.add_row("ISP",             abuse["isp"])
            ab_table.add_row("Usage Type",      abuse["usage_type"])
            ab_table.add_row("Last Reported",   str(abuse["last_reported"]))
            ab_table.add_row("Whitelisted",     "Yes" if abuse["is_whitelisted"] else "No")

            console.print(ab_table)

    # ── Final Verdict ────────────────────────────
    verdict_text = {
        "CRITICAL": "⛔ This IOC is highly malicious. Immediate action recommended.",
        "HIGH":     "🔴 This IOC has significant threat indicators. Investigate urgently.",
        "MEDIUM":   "🟡 This IOC shows suspicious activity. Monitor closely.",
        "LOW":      "🟢 This IOC appears relatively safe based on available data.",
    }
    console.print(Panel(
        f"[{color}][bold]{verdict_text[level]}[/bold][/{color}]",
        title="[bold]Verdict[/bold]",
        border_style=color
    ))
    console.print()


# ─────────────────────────────────────────────
#  OUTPUT: Save JSON Log (SIEM-ingestible)
# ─────────────────────────────────────────────
def save_log(ioc: str, ioc_type: str, vt: dict, abuse: dict, score: float, level: str):
    """
    Saves the full enrichment result to a JSON log file.
    This format is ingestible by SIEMs like Splunk or Microsoft Sentinel.
    Each run appends a new record to the log file.
    """
    log_entry = {
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        "ioc":          ioc,
        "ioc_type":     ioc_type,
        "threat_score": score,
        "threat_level": level,
        "virustotal":   vt,
        "abuseipdb":    abuse if abuse else {},
    }

    log_file = LOG_DIR / "threat_intel_log.json"

    # Load existing logs or start fresh
    existing = []
    if log_file.exists():
        try:
            with open(log_file, "r") as f:
                existing = json.load(f)
        except json.JSONDecodeError:
            existing = []

    existing.append(log_entry)

    with open(log_file, "w") as f:
        json.dump(existing, f, indent=2)

    console.print(f"[dim]📄 Log saved to: {log_file}[/dim]")


# ─────────────────────────────────────────────
#  MAIN: Entry Point
# ─────────────────────────────────────────────
def main():
    """
    Main entry point for the CLI tool.
    Parses arguments, orchestrates API queries,
    generates the report, and saves the log.
    """
    parser = argparse.ArgumentParser(
        description="IOC Threat Intelligence Module — lookup IPs, domains, and file hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_module.py 8.8.8.8
  python ioc_module.py malicious-domain.com
  python ioc_module.py d41d8cd98f00b204e9800998ecf8427e
        """
    )
    parser.add_argument(
        "ioc",
        help="The IOC to investigate: an IP address, domain, or file hash"
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Skip saving results to the JSON log file"
    )

    args = parser.parse_args()
    ioc  = args.ioc.strip()

    # Step 1: Detect the IOC type
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print(f"[red]Error:[/red] Could not determine IOC type for '{ioc}'.")
        console.print("Please provide a valid IP address, domain name, or file hash.")
        sys.exit(1)

    console.print(f"\n[cyan]🔍 Analysing[/cyan] [bold]{ioc}[/bold] "
                  f"[dim](detected type: {ioc_type})[/dim]")

    # Step 2: Query VirusTotal
    console.print("[dim]  → Querying VirusTotal...[/dim]")
    vt_result = query_virustotal(ioc, ioc_type)

    # Step 3: Query AbuseIPDB (only for IP addresses)
    abuse_result = None
    if ioc_type == "ip":
        console.print("[dim]  → Querying AbuseIPDB...[/dim]")
        abuse_result = query_abuseipdb(ioc)

    # Step 4: Calculate threat score
    score, level, color = calculate_threat_level(vt_result, abuse_result)

    # Step 5: Print the report
    print_report(ioc, ioc_type, vt_result, abuse_result, score, level, color)

    # Step 6: Save to JSON log
    if not args.no_log:
        save_log(ioc, ioc_type, vt_result, abuse_result, score, level)


if __name__ == "__main__":
    main()
