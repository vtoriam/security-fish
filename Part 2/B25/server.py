"""
=============================================================
  IOC Threat Intelligence Module — Backend Server
  ------------------------------------------------
  A lightweight Flask server that:
    1. Serves the dashboard HTML
    2. Proxies VirusTotal & AbuseIPDB API calls
       (browsers can't call these directly due to CORS)
    3. Saves results to a JSON log file

  Run with:
    python server.py

  Then open:
    http://localhost:5000
=============================================================
"""

import re
import json
import datetime
import requests
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ─────────────────────────────────────────────
#  CONFIGURATION — paste your API keys here
# ─────────────────────────────────────────────
# ── Read keys from ioc_module.py automatically ──────────────────────
import importlib.util, pathlib

def _load_keys():
    p = pathlib.Path(__file__).parent / "ioc_module.py"
    if not p.exists():
        return "YOUR_VIRUSTOTAL_API_KEY", "YOUR_ABUSEIPDB_API_KEY"
    spec = importlib.util.spec_from_file_location("ioc_module", p)
    mod  = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod.VIRUSTOTAL_API_KEY, mod.ABUSEIPDB_API_KEY
    except Exception:
        return "YOUR_VIRUSTOTAL_API_KEY", "YOUR_ABUSEIPDB_API_KEY"

VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY = _load_keys()

LOG_DIR  = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "threat_intel_log.json"

app = Flask(__name__, static_folder=".")
CORS(app)


# ─────────────────────────────────────────────
#  HELPER: Detect IOC Type
# ─────────────────────────────────────────────
def detect_ioc_type(ioc: str) -> str:
    ip_re     = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    domain_re = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    hash_lens = {32: "md5", 40: "sha1", 64: "sha256"}

    if ip_re.match(ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]+$", ioc) and len(ioc) in hash_lens:
        return hash_lens[len(ioc)]
    if domain_re.match(ioc):
        return "domain"
    return "unknown"


# ─────────────────────────────────────────────
#  HELPER: Query VirusTotal
# ─────────────────────────────────────────────
def query_virustotal(ioc: str, ioc_type: str) -> dict:
    base    = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    endpoints = {
        "ip":     f"{base}/ip_addresses/{ioc}",
        "domain": f"{base}/domains/{ioc}",
        "md5":    f"{base}/files/{ioc}",
        "sha1":   f"{base}/files/{ioc}",
        "sha256": f"{base}/files/{ioc}",
    }

    url = endpoints.get(ioc_type)
    if not url:
        return {"error": "Unsupported IOC type"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        if r.status_code == 404:
            return {"error": "Not found in VirusTotal database"}
        if r.status_code != 200:
            return {"error": f"VirusTotal HTTP {r.status_code}"}

        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        result = {
            "malicious":      malicious,
            "suspicious":     suspicious,
            "harmless":       harmless,
            "undetected":     undetected,
            "total_engines":  total,
            "reputation":     attrs.get("reputation", 0),
        }

        if ioc_type == "ip":
            result.update({
                "country": attrs.get("country", "N/A"),
                "owner":   attrs.get("as_owner", "N/A"),
                "asn":     attrs.get("asn", "N/A"),
            })
        elif ioc_type == "domain":
            result.update({
                "registrar":    attrs.get("registrar", "N/A"),
                "created":      attrs.get("creation_date", "N/A"),
                "categories":   list(attrs.get("categories", {}).values())[:3],
            })
        elif ioc_type in ("md5", "sha1", "sha256"):
            result.update({
                "file_name": attrs.get("meaningful_name", "N/A"),
                "file_type": attrs.get("type_description", "N/A"),
                "file_size": attrs.get("size", "N/A"),
                "tags":      attrs.get("tags", [])[:5],
            })

        return result

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to VirusTotal"}


# ─────────────────────────────────────────────
#  HELPER: Query AbuseIPDB
# ─────────────────────────────────────────────
def query_abuseipdb(ip: str) -> dict:
    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key"}
        if r.status_code != 200:
            return {"error": f"AbuseIPDB HTTP {r.status_code}"}

        d = r.json().get("data", {})
        return {
            "confidence":   d.get("abuseConfidenceScore", 0),
            "country":      d.get("countryCode", "N/A"),
            "isp":          d.get("isp", "N/A"),
            "domain":       d.get("domain", "N/A"),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt") or "Never",
            "is_whitelisted": d.get("isWhitelisted", False),
            "usage_type":   d.get("usageType", "N/A"),
        }

    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to AbuseIPDB"}


# ─────────────────────────────────────────────
#  HELPER: Calculate Threat Score
# ─────────────────────────────────────────────
def calculate_threat(vt: dict, abuse: dict | None) -> tuple[float, str]:
    score = 0.0

    if "malicious" in vt:
        mal   = vt["malicious"]
        total = vt.get("total_engines", 1) or 1
        if mal > 0:
            score += 30
            score += min((mal / total) * 50, 50)

    if abuse and "confidence" in abuse:
        score += abuse["confidence"] * 0.2

    score = min(round(score, 1), 100)

    if score >= 75:   level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    else:             level = "LOW"

    return score, level


# ─────────────────────────────────────────────
#  HELPER: Save to JSON log
# ─────────────────────────────────────────────
def save_log(ioc, ioc_type, vt, abuse, score, level):
    entry = {
        "timestamp":    datetime.datetime.utcnow().isoformat() + "Z",
        "ioc":          ioc,
        "ioc_type":     ioc_type,
        "threat_score": score,
        "threat_level": level,
        "virustotal":   vt,
        "abuseipdb":    abuse or {},
    }
    existing = []
    if LOG_FILE.exists():
        try:
            existing = json.loads(LOG_FILE.read_text())
        except Exception:
            existing = []
    existing.append(entry)
    LOG_FILE.write_text(json.dumps(existing, indent=2))


# ─────────────────────────────────────────────
#  ROUTE: Serve dashboard
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "dashboard.html")


# ─────────────────────────────────────────────
#  ROUTE: Main lookup endpoint
# ─────────────────────────────────────────────
@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.get_json()
    ioc  = (data.get("ioc") or "").strip()

    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        return jsonify({"error": f"Cannot determine IOC type for: {ioc}"}), 400

    # Query APIs
    vt    = query_virustotal(ioc, ioc_type)
    abuse = query_abuseipdb(ioc) if ioc_type == "ip" else None

    # Score
    score, level = calculate_threat(vt, abuse)

    # Log
    save_log(ioc, ioc_type, vt, abuse, score, level)

    return jsonify({
        "ioc":        ioc,
        "ioc_type":   ioc_type,
        "score":      score,
        "level":      level,
        "virustotal": vt,
        "abuseipdb":  abuse,
    })


# ─────────────────────────────────────────────
#  ROUTE: Fetch log history
# ─────────────────────────────────────────────
@app.route("/log", methods=["GET"])
def get_log():
    if not LOG_FILE.exists():
        return jsonify([])
    try:
        return jsonify(json.loads(LOG_FILE.read_text()))
    except Exception:
        return jsonify([])


# ─────────────────────────────────────────────
#  ROUTE: Clear log
# ─────────────────────────────────────────────
@app.route("/log", methods=["DELETE"])
def clear_log():
    if LOG_FILE.exists():
        LOG_FILE.write_text("[]")
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("\n  IOC Threat Intelligence Server")
    print("  ─────────────────────────────────")
    print("  Open your browser at: http://localhost:5000\n")
    app.run(debug=True, port=5000)
