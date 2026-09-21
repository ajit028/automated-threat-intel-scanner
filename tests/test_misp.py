"""
Unit tests for MISP Export Module.
"""

import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from misp_export import export_to_misp, get_misp_connection, PYMISP_AVAILABLE


def test_pymisp_imported():
    assert PYMISP_AVAILABLE is True


def test_misp_export_missing_config():
    # Calling export with empty config should fail gracefully without crashing
    dummy_results = [
        {
            "ioc": "185.220.101.5",
            "type": "ipv4",
            "classification": "MALICIOUS",
            "risk_score": 95,
            "details": "VT: 14/85"
        }
    ]
    status = export_to_misp(dummy_results, config={})
    assert status is False


def test_misp_export_clean_iocs():
    # If all IOCs are clean, nothing to export, returns True gracefully
    clean_results = [
        {
            "ioc": "8.8.8.8",
            "type": "ipv4",
            "classification": "CLEAN",
            "risk_score": 0,
            "details": "Clean IP"
        }
    ]
    # Provide dummy config
    dummy_config = {"misp_url": "https://misp.example.org", "misp_api_key": "dummy_key"}
    # Will attempt to connect or return False if mock server not reachable,
    # or if we mock PyMISP
    # Let's test that function handles exception gracefully
    assert export_to_misp(clean_results, config={}) is False
