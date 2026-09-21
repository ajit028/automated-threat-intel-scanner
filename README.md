# 🛡️ Automated Threat Intel & IOC Scanner Pipeline

![GitHub](https://img.shields.io/github/license/ajit028/automated-threat-intel-scanner)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-v0.115%2B-009688.svg)
![MISP](https://img.shields.io/badge/MISP-API%20Integration-red.svg)
![STIX 2.1](https://img.shields.io/badge/STIX-2.1%20Compliant-blueviolet.svg)
![VirusTotal](https://img.shields.io/badge/VirusTotal-v3%20API-green.svg)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-v2%20API-orange.svg)
![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)
![SOC Ready](https://img.shields.io/badge/SOC-Ready-critical.svg)

An enterprise-grade, high-throughput threat intelligence and Indicators of Compromise (IOC) scanning pipeline built for Security Operations Center (SOC) analysts, Incident Responders, and Threat Intelligence teams. Automatically extracts, enriches, risk-scores, standardizes (STIX 2.1), and exports threats directly to **MISP** and SIEM/SOAR platforms.

[Author Portfolio](https://ajit028.github.io) • [LinkedIn](https://linkedin.com/in/ajit028)

---

## 🚀 Key Capabilities

- **🔍 Multi-Type IOC Extraction**: High-speed regex parsing of raw logs, syslog, emails, and SIEM alerts for:
  - IPv4 (with RFC-1918 private IP filtering) & IPv6
  - MD5, SHA-1, and SHA-256 cryptographic hashes
  - Domains, FQDNs, URLs, and Email addresses
- **🌐 Dual Threat Feeds**: Real-time enrichment via **VirusTotal (v3)** and **AbuseIPDB (v2)**.
- **⚡ High-Throughput & Thread-Safe Cache**: Multi-threaded concurrency (`ThreadPoolExecutor`) backed by an SQLite cache in **WAL mode** for sub-millisecond lookups without rate-limit penalties.
- **📊 Composite Risk Scoring Engine**: Calculates normalized risk scores (0–100) combining malicious detection ratios, reporter confidence, and threat flags.
- **🏷️ Automated SOC Triage**: Tiers indicators into `MALICIOUS` (>70), `SUSPICIOUS` (30–70), and `CLEAN` (<30).
- **📦 Enterprise STIX 2.1 & MISP Export**:
  - Generates OASIS STIX 2.1 Indicator bundles for TAXII feeds.
  - Pushes actionable IOCs directly into **MISP (Malware Information Sharing Platform)** instances via PyMISP with automated `to_ids` tagging.
- **🚀 Async FastAPI Web Service**: Interactive REST API (`/docs`) supporting synchronous text payload scans, file uploads, STIX formatting, and automated MISP dispatch.
- **📈 Performance Benchmarking Suite**: Integrated throughput tester verifying regex extraction speed and multi-threaded throughput (>50,000 IOCs/sec extraction).

---

## 🏗️ Architecture & Pipeline Flow

```mermaid
graph TD
    A[Raw Incident Logs / SIEM Alert / API Request] -->|IOC Extractor| B(Deduplicated IOCs)
    B --> C{SQLite Cache Hit?}
    C -->|Yes (< 24h)| F[Composite Risk Scoring Engine]
    C -->|No| D{IOC Type?}
    D -->|IPv4 / IPv6| E1[AbuseIPDB API v2]
    D -->|Hash / Domain / URL| E2[VirusTotal API v3]
    E1 --> F
    E2 --> F
    F --> G{Classification}
    G -->|> 70: MALICIOUS| H[High Priority Alert]
    G -->|30-70: SUSPICIOUS| I[Analyst Review]
    G -->|< 30: CLEAN| J[Benign / Informational]
    H --> K1[STIX 2.1 JSON Bundle]
    H --> K2[MISP Event API Export]
    H --> K3[Markdown / JSON Audit Report]
    I --> K1
    I --> K2
    I --> K3
    J --> K3
```

---

## 📦 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/ajit028/automated-threat-intel-scanner.git
cd automated-threat-intel-scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys & Integrations
Set environment variables or use the CLI:
```bash
# Environment variables
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export MISP_URL="https://misp.yourdomain.local"
export MISP_API_KEY="your_misp_auth_key"
export MISP_VERIFY_CERT="false"

# Or configure via CLI:
python scanner.py config --vt-key "YOUR_KEY" --abuseipdb-key "YOUR_KEY" --misp-url "https://misp.local" --misp-key "YOUR_KEY"
python scanner.py config --show
```

---

## 🌐 FastAPI Web REST API

Run the production FastAPI service locally:
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at: **`http://localhost:8000/docs`**

### REST API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Health check & integration status (VT, AbuseIPDB, MISP) |
| `POST` | `/api/v1/scan/log` | Submit raw log text; returns JSON report or STIX 2.1 bundle |
| `POST` | `/api/v1/scan/ioc` | Submit a discrete array of IOC strings |
| `POST` | `/api/v1/scan/file` | Multipart file upload for incident log files |
| `POST` | `/api/v1/export/misp`| Push enriched threat intelligence directly to MISP |

### API Request Examples

#### 1. Scan Raw Log & Export to STIX 2.1 Bundle
```bash
curl -X POST "http://localhost:8000/api/v1/scan/log" \
     -H "Content-Type: application/json" \
     -d '{
       "log_content": "Suspicious login from 185.220.101.5 with payload http://malware.org/x.exe",
       "output_format": "stix",
       "export_to_misp": false
     }'
```

#### 2. Scan Single or Multiple IOCs
```bash
curl -X POST "http://localhost:8000/api/v1/scan/ioc" \
     -H "Content-Type: application/json" \
     -d '{
       "iocs": ["185.220.101.5", "44d88612fea8a8f36de82e1278abb02f", "evil-c2.net"],
       "output_format": "json",
       "export_to_misp": true
     }'
```

---

## 🛡️ MISP (Malware Information Sharing Platform) Export

The pipeline natively connects with MISP instances using PyMISP:
- Maps detected threat types (`ip-dst`, `domain`, `url`, `md5`, `sha256`, `email-src`).
- Sets `to_ids=True` automatically for confirmed `MALICIOUS` indicators.
- Attaches normalized composite risk scores and scan metadata as attribute comments.

### CLI MISP Export:
```bash
python scanner.py scan --input sample-data/sample_incident.log --misp-export --misp-event-name "SOC Incident #1044"
```

---

## 🛠️ CLI Usage Examples

### 1. Scan Incident Log to Markdown Report
```bash
python scanner.py scan --input sample-data/sample_incident.log --output report.md --format markdown
```

### 2. Export Detected Threats to STIX 2.1 Bundle
```bash
python scanner.py scan --input sample-data/sample_incident.log --stix-output stix_bundle.json
```

### 3. Scan a Single Indicator
```bash
python scanner.py scan --ioc "185.220.101.5"
```

### 4. Regenerate Markdown Report from JSON
```bash
python scanner.py report --json-file result.json --output audit_report.md
```

---

## ⚡ Performance Benchmarking

Run the built-in benchmark script to measure extraction and pipeline throughput:
```bash
python tests/benchmark.py --iocs 200 --threads 10
```

### Benchmark Results

| Metric | Measured Performance |
| :--- | :--- |
| **IOC Regex Extraction Speed** | **55,000+ IOCs/sec** (~3.5 MB/s log parsing) |
| **SQLite WAL Cache Read** | **4,000+ reads/sec** (< 0.2ms latency) |
| **Multi-Threaded Throughput** | **40–80 IOCs/sec** (cached/low-latency) |
| **Private IP Filtering Overhead** | **< 1% CPU utilization** |

---

## 🐳 Docker Deployment

### Run CLI Scanner via Docker:
```bash
docker build -t automated-threat-intel-scanner .
docker run --rm -v $(pwd):/app automated-threat-intel-scanner scan --input sample-data/sample_incident.log
```

### Run Full Pipeline (CLI + FastAPI Service) via Docker Compose:
```bash
docker compose up -d api
# API is accessible at http://localhost:8000/docs
```

---

## 🧪 Testing

Execute the comprehensive test suite (Unit tests, API tests, MISP tests):
```bash
pytest tests/
```

---

## 🛡️ MITRE ATT&CK® Relevance

| Technique ID | Technique Name | Pipeline Mapping |
| :--- | :--- | :--- |
| **T1588.005** | Obtain Capabilities: Known Malware | Hash matching & VirusTotal analysis |
| **T1071** | Application Layer Protocol | Domain and URL reputation scoring |
| **T1590** | Gather Victim Network Info | IP address abuse confidence calculation |
| **T1041** | Exfiltration Over C2 Channel | STIX 2.1 & MISP C2 attribute correlation |

---

## 👤 Author

**Ajit Nayak**
- Portfolio: [ajit028.github.io](https://ajit028.github.io)
- LinkedIn: [linkedin.com/in/ajit028](https://linkedin.com/in/ajit028)
- GitHub: [@ajit028](https://github.com/ajit028)

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
