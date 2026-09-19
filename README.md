# Automated Threat Intel & IOC Scanner Pipeline

Engineered a Python 3 automated triage pipeline to extract Indicators of Compromise (IOCs) from unformatted incident logs, query VirusTotal & AbuseIPDB APIs concurrently, and produce risk-scored alert summaries for SOC Tier 1 teams.

## Features

- **Regex IOC Extraction**: Automatically extracts IPv4 addresses, domain names, file hashes (MD5, SHA256), and URLs from raw text logs.
- **API Threat Enrichment**: Queries VirusTotal and AbuseIPDB concurrently with rate limiting and error handling.
- **Risk Scoring & Triage**: Calculates composite risk scores and classifies IOCs as Malicious, Suspicious, or Clean.
- **Structured Reporting**: Outputs comprehensive summary reports in JSON and Markdown formats for SOC ticket documentation.

## Installation

```bash
git clone https://github.com/ajit028/automated-threat-intel-scanner.git
cd automated-threat-intel-scanner
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py --log sample_incident.log --vt-key YOUR_VT_KEY --abuse-key YOUR_ABUSE_KEY
```

## License

MIT