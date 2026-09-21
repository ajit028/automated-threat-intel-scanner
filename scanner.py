#!/usr/bin/env python3
"""
Automated Threat Intel & IOC Scanner Pipeline
================================================
scanner.py — Main CLI entry point.

Subcommands:
    scan    Extract IOCs from a file/text and enrich via VirusTotal & AbuseIPDB
    report  Regenerate a report from a previous JSON scan result
    config  Show or set API key configuration

Usage:
    python scanner.py scan --input incident.log --output report.md --format markdown
    python scanner.py scan --ioc "185.220.101.5"
    python scanner.py scan --input incident.log --misp-export
    python scanner.py config --vt-key "YOUR_KEY" --abuseipdb-key "YOUR_KEY"
    python scanner.py config --show
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

from config import load_config, save_config
from ioc_extractor import extract_from_file, extract_iocs
from report_generator import generate_json_report, generate_markdown_report
from stix_export import generate_stix_bundle
from misp_export import export_to_misp
from cache import get_cached_result, set_cached_result

# ─── ANSI Color Codes ───────────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

VERSION = "1.1.0"

# ─── Threat Intelligence Lookups ────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> Dict[str, Any]:
    """
    Query VirusTotal v3 API for an IOC (IP, hash, domain, URL).
    Returns normalized result dict with vt_malicious, vt_total, vt_result.
    """
    if not api_key:
        return {"vt_malicious": 0, "vt_total": 0, "vt_result": "no_api_key"}

    headers = {"x-apikey": api_key}
    base_url = "https://www.virustotal.com/api/v3"
    url = None

    if ioc_type == "ipv4":
        url = f"{base_url}/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"{base_url}/domains/{ioc}"
    elif ioc_type in ("md5", "sha1", "sha256"):
        url = f"{base_url}/files/{ioc}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"{base_url}/urls/{url_id}"
    else:
        return {"vt_malicious": 0, "vt_total": 0, "vt_result": "unsupported_type"}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "vt_malicious": malicious,
                "vt_total": total,
                "vt_result": "found"
            }
        elif resp.status_code == 404:
            return {"vt_malicious": 0, "vt_total": 0, "vt_result": "not_found"}
        elif resp.status_code == 401:
            return {"vt_malicious": 0, "vt_total": 0, "vt_result": "invalid_api_key"}
        else:
            return {"vt_malicious": 0, "vt_total": 0, "vt_result": f"http_{resp.status_code}"}
    except requests.RequestException as exc:
        return {"vt_malicious": 0, "vt_total": 0, "vt_result": f"error:{exc}"}


def query_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """
    Query AbuseIPDB v2 API for an IP address.
    Returns normalized result with abuseipdb_confidence, abuseipdb_reports.
    """
    if not api_key:
        return {"abuseipdb_confidence": 0, "abuseipdb_reports": 0, "abuseipdb_result": "no_api_key"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseipdb_confidence": data.get("abuseConfidenceScore", 0),
                "abuseipdb_reports": data.get("totalReports", 0),
                "abuseipdb_country": data.get("countryCode", ""),
                "abuseipdb_result": "found"
            }
        elif resp.status_code == 401:
            return {"abuseipdb_confidence": 0, "abuseipdb_reports": 0, "abuseipdb_result": "invalid_api_key"}
        else:
            return {"abuseipdb_confidence": 0, "abuseipdb_reports": 0, "abuseipdb_result": f"http_{resp.status_code}"}
    except requests.RequestException as exc:
        return {"abuseipdb_confidence": 0, "abuseipdb_reports": 0, "abuseipdb_result": f"error:{exc}"}


# ─── Risk Scoring ────────────────────────────────────────────────────────────

def calculate_risk_score(vt_data: Dict, abuse_data: Optional[Dict] = None) -> int:
    """
    Composite risk score 0-100:
     - VirusTotal: (malicious/total) * 70 points
     - AbuseIPDB confidence: scaled to 30 points
    """
    score = 0.0

    # VirusTotal component
    vt_total = vt_data.get("vt_total", 0)
    vt_malicious = vt_data.get("vt_malicious", 0)
    if vt_total > 0:
        score += (vt_malicious / vt_total) * 70

    # AbuseIPDB component
    if abuse_data:
        confidence = abuse_data.get("abuseipdb_confidence", 0)
        score += (confidence / 100.0) * 30

    return min(int(score), 100)


def classify(risk_score: int) -> str:
    """Map numeric risk score to a classification tier."""
    if risk_score > 70:
        return "MALICIOUS"
    elif risk_score >= 30:
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def classification_color(label: str) -> str:
    """Return ANSI color prefix for a classification label."""
    return {
        "MALICIOUS": RED + BOLD,
        "SUSPICIOUS": YELLOW + BOLD,
        "CLEAN": GREEN,
    }.get(label, RESET)


# ─── Core Scan Logic ─────────────────────────────────────────────────────────

def enrich_ioc(
    ioc: str, ioc_type: str, config: Dict, rate_limit: float = 1.0
) -> Dict[str, Any]:
    """
    Perform full enrichment for a single IOC:
    1. Check SQLite cache (< 24h old)
    2. Query VirusTotal (if applicable)
    3. Query AbuseIPDB (if IP)
    4. Calculate risk score + classification & cache result
    Returns a unified result record.
    """
    cached = get_cached_result(ioc)
    if cached:
        cached["cached"] = True
        return cached

    vt_data = {"vt_malicious": 0, "vt_total": 0, "vt_result": "skipped"}
    abuse_data = None

    # VirusTotal lookup — supported for IP, domain, hash, URL
    if ioc_type in ("ipv4", "domain", "md5", "sha1", "sha256", "url"):
        vt_data = query_virustotal(ioc, ioc_type, config.get("vt_api_key", ""))

    if rate_limit > 0:
        time.sleep(rate_limit)

    # AbuseIPDB lookup — IPs only
    if ioc_type == "ipv4":
        abuse_data = query_abuseipdb(ioc, config.get("abuseipdb_api_key", ""))

    risk_score = calculate_risk_score(vt_data, abuse_data)
    classification = classify(risk_score)

    # Build human-readable details string
    detail_parts = []
    if vt_data.get("vt_total", 0) > 0:
        detail_parts.append(f"VT: {vt_data['vt_malicious']}/{vt_data['vt_total']}")
    if abuse_data and abuse_data.get("abuseipdb_confidence", 0) > 0:
        detail_parts.append(
            f"AbuseIPDB: {abuse_data['abuseipdb_confidence']}% confidence "
            f"({abuse_data.get('abuseipdb_reports', 0)} reports)"
        )
    if not detail_parts:
        detail_parts.append(f"VT: {vt_data.get('vt_result', 'no data')}")

    res = {
        "ioc": ioc,
        "type": ioc_type,
        "risk_score": risk_score,
        "classification": classification,
        "details": " | ".join(detail_parts),
        "vt": vt_data,
        "abuseipdb": abuse_data or {},
        "cached": False
    }
    set_cached_result(ioc, ioc_type, res)
    return res


def print_result(record: Dict) -> None:
    """Print a single enriched IOC result to terminal with color coding."""
    label = record["classification"]
    color = classification_color(label)
    ioc = record["ioc"]
    ioc_type = record["type"].upper()
    risk = record["risk_score"]
    details = record["details"]
    print(
        f"  {color}[{label}]{RESET} {BOLD}{ioc}{RESET} "
        f"{DIM}({ioc_type}){RESET} | "
        f"Risk Score: {color}{risk}/100{RESET} | {details}"
    )


def scan_iocs_sync(ioc_dict: Dict[str, List[str]], config: Dict, verbose: bool = True) -> List[Dict]:
    """
    Programmatic helper to enrich an IOC dictionary.
    """
    ioc_pairs: List[tuple] = []
    for ioc_type, ioc_list in ioc_dict.items():
        for ioc in ioc_list:
            ioc_pairs.append((ioc, ioc_type))

    total = len(ioc_pairs)
    if total == 0:
        return []

    max_threads = config.get("max_threads", 5)
    rate_limit = config.get("rate_limit_seconds", 1.0)

    results: List[Dict] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures_map = {
            executor.submit(enrich_ioc, ioc, ioc_type, config, rate_limit): (ioc, ioc_type)
            for ioc, ioc_type in ioc_pairs
        }
        for future in as_completed(futures_map):
            completed += 1
            record = future.result()
            results.append(record)
            if verbose:
                print(f"  {DIM}[{completed}/{total}]{RESET} Scanning...", end="\r")
                print_result(record)

    return results


def run_scan(args: argparse.Namespace, config: Dict) -> List[Dict]:
    """
    Main scan orchestration:
    1. Extract IOCs from input
    2. Flatten into (ioc, type) pairs
    3. Enrich concurrently
    4. Print results + summary
    Returns list of enriched result records.
    """
    # ── Collect IOCs ──────────────────────────────────────────────────────
    all_iocs: Dict[str, List[str]] = {}

    if hasattr(args, "ioc") and args.ioc:
        # Single IOC mode: auto-detect type
        from ioc_extractor import extract_iocs as _ei
        all_iocs = _ei(args.ioc)
    elif hasattr(args, "input") and args.input:
        if args.input == "-":
            text = sys.stdin.read()
            all_iocs = extract_iocs(text)
        else:
            all_iocs = extract_from_file(args.input)
    else:
        print(f"{RED}[-] Provide --input <file> or --ioc <value>{RESET}")
        sys.exit(1)

    total = sum(len(v) for v in all_iocs.values())
    if total == 0:
        print(f"{YELLOW}[!] No IOCs found in input.{RESET}")
        return []

    print(f"\n{CYAN}{BOLD}[+] Threat Intel Scanner v{VERSION}{RESET}")
    print(f"{CYAN}[+] Loaded {BOLD}{total}{RESET}{CYAN} unique IOCs from input{RESET}")
    max_threads = config.get("max_threads", 5)
    rate_limit = config.get("rate_limit_seconds", 1.0)
    print(
        f"{CYAN}[+] Querying VirusTotal & AbuseIPDB with {max_threads} threads "
        f"(rate limit: {rate_limit}s/req){RESET}\n"
    )

    results = scan_iocs_sync(all_iocs, config, verbose=True)

    # ── Summary ───────────────────────────────────────────────────────────
    malicious_count = sum(1 for r in results if r["classification"] == "MALICIOUS")
    suspicious_count = sum(1 for r in results if r["classification"] == "SUSPICIOUS")
    clean_count = sum(1 for r in results if r["classification"] == "CLEAN")

    print(f"\n{BOLD}{'─' * 60}{RESET}")
    print(
        f"{CYAN}[+] Scan complete. "
        f"Total: {total} | "
        f"{RED}Malicious: {malicious_count}{RESET} | "
        f"{YELLOW}Suspicious: {suspicious_count}{RESET} | "
        f"{GREEN}Clean: {clean_count}{RESET}"
    )

    return results


# ─── Subcommand Handlers ─────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> None:
    """Handle `scanner.py scan` subcommand."""
    config = load_config()
    results = run_scan(args, config)
    if not results:
        return

    if getattr(args, "stix_output", None):
        generate_stix_bundle(results, output_file=args.stix_output)

    if getattr(args, "misp_export", False):
        event_name = getattr(args, "misp_event_name", None)
        export_to_misp(results, config, event_name=event_name)

    output_file = getattr(args, "output", None)
    fmt = getattr(args, "format", "markdown")

    if output_file:
        if fmt == "json":
            generate_json_report(results, output_file=output_file)
        else:
            generate_markdown_report(results, output_file=output_file)
        print(f"{GREEN}[+] Report saved: {output_file}{RESET}")
    elif not getattr(args, "stix_output", None) and not getattr(args, "misp_export", False):
        pass


def cmd_report(args: argparse.Namespace) -> None:
    """Handle `scanner.py report` — regenerate report from JSON file."""
    if not os.path.exists(args.json_file):
        print(f"{RED}[-] File not found: {args.json_file}{RESET}")
        sys.exit(1)

    with open(args.json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data if isinstance(data, list) else data.get("results", [])
    output = getattr(args, "output", "report.md")
    generate_markdown_report(results, output_file=output)
    print(f"{GREEN}[+] Report regenerated: {output}{RESET}")


def cmd_config(args: argparse.Namespace) -> None:
    """Handle `scanner.py config` subcommand."""
    if args.show:
        config = load_config()
        print(f"\n{BOLD}Current Configuration:{RESET}")
        vt_key = config.get("vt_api_key", "")
        ab_key = config.get("abuseipdb_api_key", "")
        misp_url = config.get("misp_url", "")
        misp_key = config.get("misp_api_key", "")
        print(f"  VT API Key:        {'*' * len(vt_key[:6])}... ({len(vt_key)} chars)" if vt_key else "  VT API Key:        (not set)")
        print(f"  AbuseIPDB API Key: {'*' * len(ab_key[:6])}... ({len(ab_key)} chars)" if ab_key else "  AbuseIPDB API Key: (not set)")
        print(f"  MISP URL:          {misp_url if misp_url else '(not set)'}")
        print(f"  MISP API Key:      {'*' * len(misp_key[:6])}... ({len(misp_key)} chars)" if misp_key else "  MISP API Key:      (not set)")
        print(f"  MISP Verify SSL:   {config.get('misp_verify_cert', False)}")
        print(f"  Max Threads:       {config.get('max_threads', 5)}")
        print(f"  Rate Limit:        {config.get('rate_limit_seconds', 1.0)}s\n")
    else:
        save_config(
            vt_key=getattr(args, "vt_key", None),
            abuseipdb_key=getattr(args, "abuseipdb_key", None),
            misp_url=getattr(args, "misp_url", None),
            misp_key=getattr(args, "misp_key", None),
            misp_verify_cert=getattr(args, "misp_verify_cert", None),
            rate_limit=getattr(args, "rate_limit", None),
            max_threads=getattr(args, "max_threads", None),
        )


# ─── CLI Argument Parser ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            f"{BOLD}Automated Threat Intel & IOC Scanner{RESET} v{VERSION}\n"
            "Extracts, enriches, and risk-scores Indicators of Compromise (IOCs)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py scan --input incident.log --output report.md\n"
            "  python scanner.py scan --ioc 185.220.101.5\n"
            "  python scanner.py scan --input incident.log --misp-export\n"
            "  python scanner.py scan --input incident.log --format json --output result.json\n"
            "  python scanner.py report --json-file result.json --output report.md\n"
            "  python scanner.py config --vt-key YOURKEY --abuseipdb-key YOURKEY\n"
            "  python scanner.py config --show"
        )
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Extract and enrich IOCs from a file or direct input")
    group = scan_p.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", "--log", "-i", metavar="FILE", dest="input",
                       help="Path to incident log / text file to scan (use '-' for stdin)")
    group.add_argument("--ioc", metavar="IOC",
                       help="Single IOC to scan (IP, hash, domain, etc.)")
    scan_p.add_argument("--output", "-o", metavar="FILE",
                       help="Output file path for the report")
    scan_p.add_argument("--stix-output", metavar="FILE",
                       help="Export detected IOCs as a STIX 2.1 JSON bundle")
    scan_p.add_argument("--misp-export", action="store_true",
                       help="Export detected malicious/suspicious IOCs to MISP")
    scan_p.add_argument("--misp-event-name", metavar="NAME",
                       help="Custom name for the MISP event")
    scan_p.add_argument("--format", "-f", choices=["markdown", "json"],
                       default="markdown", help="Output report format (default: markdown)")
    scan_p.set_defaults(func=cmd_scan)

    # ── report ─────────────────────────────────────────────────────────────
    rep_p = sub.add_parser("report", help="Regenerate a report from a previous JSON scan result")
    rep_p.add_argument("--json-file", "-j", required=True, metavar="FILE",
                       dest="json_file", help="Path to a JSON results file")
    rep_p.add_argument("--output", "-o", default="report.md", metavar="FILE",
                       help="Output Markdown report path")
    rep_p.set_defaults(func=cmd_report)

    # ── config ─────────────────────────────────────────────────────────────
    cfg_p = sub.add_parser("config", help="View or set API keys and settings")
    cfg_p.add_argument("--vt-key", dest="vt_key", metavar="KEY",
                       help="Set VirusTotal API key")
    cfg_p.add_argument("--abuseipdb-key", dest="abuseipdb_key", metavar="KEY",
                       help="Set AbuseIPDB API key")
    cfg_p.add_argument("--misp-url", dest="misp_url", metavar="URL",
                       help="Set MISP instance URL")
    cfg_p.add_argument("--misp-key", dest="misp_key", metavar="KEY",
                       help="Set MISP API key")
    cfg_p.add_argument("--misp-verify-cert", dest="misp_verify_cert", type=bool,
                       help="Verify SSL certificate for MISP (True/False)")
    cfg_p.add_argument("--rate-limit", dest="rate_limit", type=float,
                       help="Rate limit per request in seconds")
    cfg_p.add_argument("--max-threads", dest="max_threads", type=int,
                       help="Max concurrent enrichment threads")
    cfg_p.add_argument("--show", action="store_true",
                       help="Print current configuration")
    cfg_p.set_defaults(func=cmd_config)

    return parser


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] not in ["scan", "report", "config", "-h", "--help"]:
        sys.argv.insert(1, "scan")
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
