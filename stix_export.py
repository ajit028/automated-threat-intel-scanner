"""
STIX 2.1 Export Module
======================
Exports enriched IOC scan results into standardized STIX 2.1 JSON bundles
for enterprise threat intelligence platform (TIP) sharing / TAXII integration.
"""

import json
import uuid
import datetime
from typing import List, Dict, Any

def generate_stix_bundle(scan_results: List[Dict[str, Any]], output_file: str = None) -> Dict[str, Any]:
    """
    Convert enriched scan results into a STIX 2.1 Bundle dictionary.
    
    Parameters
    ----------
    scan_results : List of enriched IOC dicts.
    output_file  : Optional file path to write the STIX JSON.

    Returns
    -------
    Dict representing the STIX 2.1 Bundle.
    """
    bundle_id = f"bundle--{uuid.uuid4()}"
    created_time = datetime.datetime.utcnow().isoformat() + "Z"
    
    objects = []

    for idx, r in enumerate(scan_results):
        ioc = r.get("ioc", "")
        ioc_type = r.get("type", "").lower()
        classification = r.get("classification", "UNKNOWN")
        risk_score = r.get("risk_score", 0)
        details = r.get("details", "")
        
        # Map IOC type to STIX pattern
        pattern = ""
        stix_type = "indicator"
        indicator_id = f"indicator--{uuid.uuid4()}"
        
        if ioc_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{ioc}']"
        elif ioc_type == "ipv6":
            pattern = f"[ipv6-addr:value = '{ioc}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc}']"
        elif ioc_type in ("md5", "sha1", "sha256"):
            hash_name = ioc_type.upper()
            pattern = f"[file:hashes.'{hash_name}' = '{ioc}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{ioc}']"
        elif ioc_type == "email":
            pattern = f"[email-addr:value = '{ioc}']"
        else:
            pattern = f"[artifact:payload_bin = '{ioc}']"

        labels = ["malicious-activity" if classification == "MALICIOUS" else "suspicious-activity"]
        if classification == "CLEAN":
            labels = ["benign"]

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": created_time,
            "modified": created_time,
            "name": f"Detected IOC: {ioc} ({classification})",
            "description": f"Risk Score: {risk_score}/100. Details: {details}",
            "pattern_type": "stix",
            "pattern": pattern,
            "pattern_version": "2.1",
            "valid_from": created_time,
            "labels": labels,
            "kill_chain_phases": [
                {
                    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                    "phase_name": "delivery"
                }
            ],
            "custom_properties": {
                "x_risk_score": risk_score,
                "x_classification": classification,
                "x_scanner": "Automated Threat Intel & IOC Scanner v1.0.0"
            }
        }
        objects.append(indicator_obj)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(bundle, f, indent=2)
            print(f"[+] STIX 2.1 Bundle saved to {output_file}")
        except Exception as exc:
            print(f"[-] Failed to write STIX bundle: {exc}")

    return bundle
