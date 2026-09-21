"""
FastAPI Web API Wrapper for Automated Threat Intel & IOC Scanner
================================================================
Provides REST API endpoints for real-time log scanning, IOC enrichment,
STIX 2.1 bundle generation, and MISP event dispatching.
"""

import os
import sys
import tempfile
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Ensure root scanner directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import load_config
from ioc_extractor import extract_iocs, count_iocs
from scanner import scan_iocs_sync, enrich_ioc
from stix_export import generate_stix_bundle
from misp_export import export_to_misp

# ─── FastAPI App Initialization ──────────────────────────────────────────────

app = FastAPI(
    title="Automated Threat Intel & IOC Scanner API",
    description=(
        "Enterprise-grade Threat Intelligence API for Security Operations Centers (SOC). "
        "Extracts, enriches, and scores IOCs from raw logs, generates STIX 2.1 bundles, "
        "and exports directly to MISP."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for SOC dashboard integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Data Models ─────────────────────────────────────────────────────────────

class OutputFormat(str, Enum):
    json = "json"
    stix = "stix"

class ScanLogRequest(BaseModel):
    log_content: str = Field(..., description="Raw incident log or text payload to extract and scan IOCs from.")
    output_format: OutputFormat = Field(default=OutputFormat.json, description="Format of the response: 'json' or 'stix'")
    export_to_misp: bool = Field(default=False, description="Whether to automatically push malicious IOCs to MISP")
    misp_event_name: Optional[str] = Field(default=None, description="Custom title for the MISP event if exported")

class ScanIOCRequest(BaseModel):
    iocs: List[str] = Field(..., description="List of IOCs (IPs, hashes, domains, URLs, emails) to enrich.")
    output_format: OutputFormat = Field(default=OutputFormat.json, description="Format of the response: 'json' or 'stix'")
    export_to_misp: bool = Field(default=False, description="Whether to export malicious items to MISP")

class SingleIOCScanRequest(BaseModel):
    ioc: str = Field(..., description="Single indicator value (e.g., '185.220.101.5')")
    ioc_type: Optional[str] = Field(default=None, description="Optional IOC type hint (ipv4, domain, md5, sha256, etc.)")

class MISPExportRequest(BaseModel):
    scan_results: List[Dict[str, Any]] = Field(..., description="List of enriched scan results to export")
    event_name: Optional[str] = Field(default=None, description="Custom title for the MISP event")

# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
async def root():
    """Service status and meta endpoint."""
    return {
        "service": "Automated Threat Intel Scanner API",
        "version": "1.1.0",
        "status": "operational",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "scan_log": "/api/v1/scan/log",
            "scan_ioc": "/api/v1/scan/ioc",
            "scan_file": "/api/v1/scan/file",
            "export_misp": "/api/v1/export/misp"
        }
    }


@app.get("/health", tags=["System"])
async def health_check():
    """Health check verifying configuration and cache status."""
    config = load_config()
    vt_configured = bool(config.get("vt_api_key"))
    abuse_configured = bool(config.get("abuseipdb_api_key"))
    misp_configured = bool(config.get("misp_url") and config.get("misp_api_key"))
    
    return {
        "status": "healthy",
        "version": "1.1.0",
        "integrations": {
            "virustotal": "configured" if vt_configured else "unconfigured (mock/clean mode)",
            "abuseipdb": "configured" if abuse_configured else "unconfigured (mock/clean mode)",
            "misp": "configured" if misp_configured else "unconfigured"
        }
    }


@app.post("/api/v1/scan/log", tags=["Scanning"])
@app.post("/scan/log", tags=["Scanning"])
async def scan_log_endpoint(payload: ScanLogRequest):
    """
    Extract IOCs from raw incident log text, enrich them concurrently,
    and return structured JSON or STIX 2.1 Threat Report.
    """
    extracted = extract_iocs(payload.log_content)
    total_found = count_iocs(extracted)

    if total_found == 0:
        return {
            "total_iocs": 0,
            "message": "No valid Indicators of Compromise (IOCs) found in submitted text.",
            "results": []
        }

    config = load_config()
    results = scan_iocs_sync(extracted, config, verbose=False)

    # Optional MISP export
    misp_status = None
    if payload.export_to_misp:
        misp_status = export_to_misp(results, config, event_name=payload.misp_event_name)

    # Return STIX bundle or JSON
    if payload.output_format == OutputFormat.stix:
        bundle = generate_stix_bundle(results)
        if payload.export_to_misp:
            bundle["misp_exported"] = misp_status
        return bundle

    malicious = sum(1 for r in results if r.get("classification") == "MALICIOUS")
    suspicious = sum(1 for r in results if r.get("classification") == "SUSPICIOUS")
    clean = sum(1 for r in results if r.get("classification") == "CLEAN")

    return {
        "status": "success",
        "total_iocs": len(results),
        "summary": {
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean
        },
        "misp_exported": misp_status if payload.export_to_misp else None,
        "results": results
    }


@app.post("/api/v1/scan/ioc", tags=["Scanning"])
@app.post("/scan/ioc", tags=["Scanning"])
async def scan_ioc_endpoint(payload: ScanIOCRequest):
    """
    Enrich a discrete list of IOC strings directly.
    """
    if not payload.iocs:
        raise HTTPException(status_code=400, detail="IOC list cannot be empty.")

    # Combine IOCs into space-separated string for multi-type extractor parsing
    text = " ".join(payload.iocs)
    extracted = extract_iocs(text, filter_private=False)
    
    config = load_config()
    results = scan_iocs_sync(extracted, config, verbose=False)

    if payload.export_to_misp:
        export_to_misp(results, config)

    if payload.output_format == OutputFormat.stix:
        return generate_stix_bundle(results)

    return {
        "status": "success",
        "total_scanned": len(results),
        "results": results
    }


@app.post("/api/v1/scan/file", tags=["Scanning"])
async def scan_file_endpoint(
    file: UploadFile = File(...),
    output_format: OutputFormat = Form(OutputFormat.json),
    export_to_misp_flag: bool = Form(False)
):
    """
    Upload a log file (e.g., auth.log, syslog, incident.txt) for automated extraction and scanning.
    """
    content_bytes = await file.read()
    try:
        text = content_bytes.decode("utf-8", errors="ignore")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {exc}")

    extracted = extract_iocs(text)
    total_found = count_iocs(extracted)

    if total_found == 0:
        return {
            "filename": file.filename,
            "total_iocs": 0,
            "message": "No Indicators of Compromise found.",
            "results": []
        }

    config = load_config()
    results = scan_iocs_sync(extracted, config, verbose=False)

    if export_to_misp_flag:
        export_to_misp(results, config, event_name=f"Log File Scan: {file.filename}")

    if output_format == OutputFormat.stix:
        return generate_stix_bundle(results)

    return {
        "filename": file.filename,
        "total_iocs": len(results),
        "results": results
    }


@app.post("/api/v1/export/misp", tags=["Integrations"])
async def export_misp_endpoint(payload: MISPExportRequest):
    """
    Directly push pre-existing or external scan results to MISP instance.
    """
    config = load_config()
    success = export_to_misp(payload.scan_results, config, event_name=payload.event_name)
    if not success:
        raise HTTPException(status_code=502, detail="Failed to push attributes to MISP instance.")
    return {"status": "success", "message": "IOCs successfully dispatched to MISP instance."}


# ─── Standalone Runner ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("[*] Starting Threat Intel Scanner API on http://127.0.0.1:8000 ...")
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
