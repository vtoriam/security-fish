# IOC Threat Intelligence Module
## Cybersecurity Assignment

---

## Overview

This module queries public threat intelligence APIs to **enrich Indicators of Compromise (IOCs)** — suspicious IPs, domains, and file hashes — and outputs structured threat reports suitable for both human review and SIEM ingestion.

---

## Files

```
threat_intel/
├── ioc_module.py       ← Main Python CLI tool
├── dashboard.html      ← Web dashboard (open in browser)
├── requirements.txt    ← Python dependencies
├── README.md           ← This file
└── logs/
    └── threat_intel_log.json   ← Auto-created on first run
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Get free API keys

| API        | Register at                              | Free limit       |
|------------|------------------------------------------|------------------|
| VirusTotal | https://www.virustotal.com/gui/join-us   | 500 requests/day |
| AbuseIPDB  | https://www.abuseipdb.com/register       | 1000 requests/day|

### 3. Add your API keys to ioc_module.py
```python
VIRUSTOTAL_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY  = "your_key_here"
```

---

## Usage

### CLI Tool
```bash
# Analyse an IP address
python ioc_module.py 185.220.101.45

# Analyse a domain
python ioc_module.py malicious-domain.com

# Analyse a file hash (MD5, SHA1, or SHA256)
python ioc_module.py d41d8cd98f00b204e9800998ecf8427e

# Skip saving to log
python ioc_module.py 8.8.8.8 --no-log
```

### Web Dashboard
Open `dashboard.html` in any browser. The dashboard:
- Accepts IOC input and simulates API enrichment
- Displays threat scores and source breakdowns
- Maintains a session lookup history with stats

---

## How It Works

```
User Input (IP / Domain / Hash)
         ↓
   Detect IOC Type
         ↓
   Query VirusTotal API  ──→  Malicious engine count, reputation, geo
   Query AbuseIPDB API   ──→  Abuse confidence score, report count
         ↓
   Calculate Threat Score (0–100)
         ↓
   Output:
     - Rich CLI report (colour-coded)
     - JSON log entry (SIEM-ingestible)
```

---

## Threat Scoring Logic

| Condition                          | Score Added        |
|------------------------------------|--------------------|
| Any VT malicious detection         | +30 base           |
| VT malicious ratio (mal/total)     | Up to +50          |
| AbuseIPDB confidence score         | × 0.2 (max +20)    |

| Score Range | Threat Level |
|-------------|-------------|
| 75–100      | CRITICAL    |
| 50–74       | HIGH        |
| 25–49       | MEDIUM      |
| 0–24        | LOW         |

---

## SIEM Integration

Each run appends a record to `logs/threat_intel_log.json` in this format:

```json
{
  "timestamp": "2024-01-15T08:00:00Z",
  "ioc": "185.220.101.45",
  "ioc_type": "ip",
  "threat_score": 96.0,
  "threat_level": "CRITICAL",
  "virustotal": { ... },
  "abuseipdb":  { ... }
}
```

This JSON format can be ingested by:
- **Splunk** — via the HTTP Event Collector (HEC)
- **Microsoft Sentinel** — via the Log Analytics API
- **IBM QRadar** — via the Log Source Management API
- **Elastic SIEM** — via Logstash or Filebeat

---

## APIs Used

### VirusTotal v3 API
- Endpoint: `https://www.virustotal.com/api/v3/`
- Supports: IP addresses, domains, file hashes
- Returns: Detection stats from 70+ antivirus engines, reputation scores, geolocation

### AbuseIPDB API v2
- Endpoint: `https://api.abuseipdb.com/api/v2/check`
- Supports: IP addresses only
- Returns: Crowd-sourced abuse confidence score, ISP, country, report history

---

## Ethical & Legal Notes

- Only analyse IOCs you have **permission** to investigate
- Submitting hashes to VirusTotal makes them **publicly searchable**
- Use private APIs or local tools (e.g. MISP) for sensitive data
- AbuseIPDB reports are crowd-sourced and may contain false positives
