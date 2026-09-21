"""
Unit and integration tests for FastAPI REST API endpoints.
"""

import sys
import os
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "endpoints" in data


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "integrations" in data


def test_scan_log_json_endpoint():
    sample_log = (
        "2026-09-21 12:00:00 Connection from 185.220.101.5 to internal host 10.0.0.5. "
        "Downloaded payload http://malware-drop.com/evil.exe with md5 44d88612fea8a8f36de82e1278abb02f"
    )
    response = client.post(
        "/api/v1/scan/log",
        json={"log_content": sample_log, "output_format": "json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_iocs"] >= 3
    assert "results" in data


def test_scan_log_stix_endpoint():
    sample_log = "Observed malicious activity from IP 45.33.32.156 targeting port 443"
    response = client.post(
        "/api/v1/scan/log",
        json={"log_content": sample_log, "output_format": "stix"}
    )
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert len(bundle["objects"]) >= 1


def test_scan_ioc_list_endpoint():
    response = client.post(
        "/api/v1/scan/ioc",
        json={"iocs": ["8.8.8.8", "1.1.1.1", "evil-example.com"], "output_format": "json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_scanned"] >= 3


def test_scan_empty_log():
    response = client.post(
        "/api/v1/scan/log",
        json={"log_content": "Clean text with no indicators whatsoever", "output_format": "json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_iocs"] == 0
