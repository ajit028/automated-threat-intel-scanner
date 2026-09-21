"""
MISP Export Module
==================
Exports enriched IOC scan results to a Malware Information Sharing Platform (MISP) instance.
"""

import sys
import datetime
from typing import List, Dict, Any

try:
    from pymisp import PyMISP, MISPEvent
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False


def get_misp_connection(config: dict) -> "PyMISP":
    """
    Initialize and return a PyMISP connection based on config.
    """
    if not PYMISP_AVAILABLE:
        raise ImportError("pymisp module is not installed. Please run `pip install pymisp`.")
    
    misp_url = config.get("misp_url", "")
    misp_key = config.get("misp_api_key", "")
    misp_verify_cert = config.get("misp_verify_cert", False)

    if not misp_url or not misp_key:
        raise ValueError("MISP URL or API key is not configured.")

    return PyMISP(misp_url, misp_key, misp_verify_cert)


def export_to_misp(scan_results: List[Dict[str, Any]], config: dict, event_name: str = None) -> bool:
    """
    Create a new MISP event and map scan results to MISP attributes.

    Parameters
    ----------
    scan_results : List of enriched IOC dicts.
    config : Configuration dict containing 'misp_url', 'misp_api_key', etc.
    event_name : Label/title for the new MISP event.

    Returns
    -------
    bool: True if export was completely successful.
    """
    if not PYMISP_AVAILABLE:
        print("[-] pymisp is not installed. Cannot export to MISP.")
        return False

    try:
        misp = get_misp_connection(config)
    except ValueError as e:
        print(f"[-] MISP configuration error: {e}")
        return False
    except Exception as e:
        print(f"[-] Failed to connect to MISP: {e}")
        return False

    if not event_name:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        event_name = f"Automated Scanner intel export - {timestamp}"

    print(f"[*] Creating new MISP event: '{event_name}'...")
    
    event = MISPEvent()
    event.info = event_name
    event.distribution = 0  # Your Organization Only
    event.threat_level_id = 2  # Medium (1=High, 2=Medium, 3=Low, 4=Undefined)
    event.analysis = 0  # Initial

    # Map our internal types to MISP attribute types
    type_mapping = {
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "domain": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "email": "email-src"
    }

    attributes_added = 0
    for res in scan_results:
        ioc = res.get("ioc")
        ioc_type = res.get("type", "unknown").lower()
        classification = res.get("classification")
        risk_score = res.get("risk_score", 0)
        
        # Only export malicious or suspicious items (or configure this)
        if classification not in ("MALICIOUS", "SUSPICIOUS"):
            continue

        misp_type = type_mapping.get(ioc_type)
        if not misp_type:
            continue

        comment = f"Scanner Risk Score: {risk_score}/100. {res.get('details', '')}"
        
        event.add_attribute(
            type=misp_type,
            value=ioc,
            comment=comment,
            to_ids=True if classification == "MALICIOUS" else False
        )
        attributes_added += 1

    if attributes_added == 0:
        print("[!] No actionable IOCs (MALICIOUS/SUSPICIOUS) to export.")
        return True

    try:
        created_event = misp.add_event(event, pythonify=True)
        print(f"[+] Successfully exported {attributes_added} attributes to MISP Event ID {created_event.id}.")
        return True
    except Exception as e:
        print(f"[-] Error pushing event into MISP server: {e}")
        return False
