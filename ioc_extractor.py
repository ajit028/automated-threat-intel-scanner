#!/usr/bin/env python3
"""
IOC Extractor Module
====================
Extracts Indicators of Compromise (IOCs) from text, files, or stdin.

Supported IOC types:
    - IPv4 addresses
    - IPv6 addresses
    - MD5 hashes
    - SHA1 hashes
    - SHA256 hashes
    - URLs (http/https)
    - Domain names
    - Email addresses

Features:
    - Private/loopback/reserved IP filtering
    - Deduplication across all types
    - Regex-based fast extraction
    - URL-domain overlap resolution
"""

import ipaddress
import json
import re
import sys
from typing import Dict, List, Set

# ─── Compiled Regex Patterns ─────────────────────────────────────────────────
# Compile once at module load for efficiency.

_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
# Simple IPv6 pattern: will be validated with ipaddress module
_RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}\b'
    r'|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_URL = re.compile(r'https?://[^\s<>"\'()\]\[]+')
_RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
# Domain: match after stripping URLs/emails to avoid overlap
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}\b'
)

# Known non-domain TLD-lookalike sequences to exclude from domain results
_DOMAIN_EXCLUSIONS: Set[str] = {"localhost"}

# ─── Private IP Detection ────────────────────────────────────────────────────

def is_private_ip(ip_str: str) -> bool:
    """
    Return True if the IP address is private, loopback, link-local,
    multicast, reserved, or unspecified — i.e. not a public routable address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_link_local
            or ip.is_unspecified
        )
    except ValueError:
        return True  # Cannot parse → treat as non-IOC


# ─── Core Extraction ─────────────────────────────────────────────────────────

def extract_iocs(text: str, filter_private: bool = True) -> Dict[str, List[str]]:
    """
    Extract all supported IOC types from *text*.

    Parameters
    ----------
    text            : Input string to scan.
    filter_private  : If True (default), omit RFC-1918 / loopback / reserved IPs.

    Returns
    -------
    dict mapping IOC type → sorted deduplicated list of matches.
    """
    results: Dict[str, Set[str]] = {
        "ipv4": set(),
        "ipv6": set(),
        "sha256": set(),
        "sha1": set(),
        "md5": set(),
        "url": set(),
        "domain": set(),
        "email": set(),
    }

    # Hashes — extract before domain to prevent hex string overlap
    for match in _RE_SHA256.finditer(text):
        results["sha256"].add(match.group())

    for match in _RE_SHA1.finditer(text):
        val = match.group()
        # Only add if it's not already captured as SHA256
        if val not in results["sha256"]:
            results["sha1"].add(val)

    for match in _RE_MD5.finditer(text):
        val = match.group()
        if val not in results["sha256"] and val not in results["sha1"]:
            results["md5"].add(val)

    # Emails — extract before domain to prevent address@domain.tld domain match
    for match in _RE_EMAIL.finditer(text):
        results["email"].add(match.group().lower())

    # URLs
    url_domains: Set[str] = set()
    for match in _RE_URL.finditer(text):
        url = match.group().rstrip(".,;)")  # strip trailing punctuation
        results["url"].add(url)
        # Extract hostname from URL to avoid double-counting in domain results
        domain_m = re.search(r'https?://([^/:?#]+)', url)
        if domain_m:
            url_domains.add(domain_m.group(1).lower())

    # IPs — extract before domain to prevent IP-looking strings being matched
    ipv4_found: Set[str] = set()
    for match in _RE_IPV4.finditer(text):
        ip = match.group()
        if filter_private and is_private_ip(ip):
            continue
        ipv4_found.add(ip)
    results["ipv4"] = ipv4_found

    # IPv6 - use validation to filter valid addresses
    ipv6_candidates: Set[str] = set()
    for match in _RE_IPV6.finditer(text):
        ip = match.group()
        # Clean up the match
        ip = ip.strip()
        if ip:
            ipv6_candidates.add(ip)
    
    # Validate IPv6 addresses
    for ip in ipv6_candidates:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 6:
                if filter_private and is_private_ip(ip):
                    continue
                results["ipv6"].add(ip)
        except ValueError:
            pass  # Not a valid IP address

    # Domains — after URLs and emails are stripped out
    # Build a shadow text with URLs/emails/IPs blanked to reduce noise
    shadow = text
    for url in results["url"]:
        shadow = shadow.replace(url, " " * len(url))
    for email in results["email"]:
        shadow = shadow.replace(email, " " * len(email))
    for ip in results["ipv4"]:
        shadow = shadow.replace(ip, " " * len(ip))
    for ip in results["ipv6"]:
        shadow = shadow.replace(ip, " " * len(ip))

    email_domains: Set[str] = {e.split("@", 1)[1].lower() for e in results["email"]}

    for match in _RE_DOMAIN.finditer(shadow):
        domain = match.group().lower()
        if (
            domain in _DOMAIN_EXCLUSIONS
            or domain in url_domains
            or domain in email_domains
            or domain in results["ipv4"]
        ):
            continue
        results["domain"].add(domain)

    return {k: sorted(list(v)) for k, v in results.items()}


def extract_from_file(filepath: str, filter_private: bool = True) -> Dict[str, List[str]]:
    """
    Read *filepath* and extract IOCs. Returns empty dict on read error.

    Parameters
    ----------
    filepath        : Path to the text file (e.g. incident log).
    filter_private  : Passed through to extract_iocs().
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        return extract_iocs(content, filter_private=filter_private)
    except OSError as exc:
        print(f"[-] Error reading file '{filepath}': {exc}", file=sys.stderr)
        return {}


def extract_from_stdin(filter_private: bool = True) -> Dict[str, List[str]]:
    """Read from stdin until EOF and extract IOCs."""
    try:
        content = sys.stdin.read()
    except KeyboardInterrupt:
        return {}
    return extract_iocs(content, filter_private=filter_private)


def count_iocs(extracted: Dict[str, List[str]]) -> int:
    """Return total number of unique IOCs across all types."""
    return sum(len(v) for v in extracted.values())


# ─── CLI (standalone use) ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract IOCs from a file or stdin and print as JSON."
    )
    parser.add_argument("file", nargs="?", help="File to scan (omit to read from stdin)")
    parser.add_argument(
        "--no-filter-private",
        action="store_true",
        help="Include private/reserved IP addresses in output",
    )
    args = parser.parse_args()

    filter_priv = not args.no_filter_private

    if args.file:
        iocs = extract_from_file(args.file, filter_private=filter_priv)
    else:
        print("[*] Reading from stdin (Ctrl+D to finish)...", file=sys.stderr)
        iocs = extract_from_stdin(filter_private=filter_priv)

    total = count_iocs(iocs)
    print(f"[+] Found {total} unique IOCs:", file=sys.stderr)
    for ioc_type, values in iocs.items():
        if values:
            print(f"    {ioc_type}: {len(values)}", file=sys.stderr)

    print(json.dumps(iocs, indent=2))