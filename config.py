"""
Configuration Management
========================
Handles API key storage and scanner configuration.
"""

import json
import os

CONFIG_FILE = "config.json"

def load_config():
    """
    Load configuration from file or environment variables.
    Returns a dict with keys:
        vt_api_key, abuseipdb_api_key, misp_url, misp_api_key, misp_verify_cert, rate_limit_seconds, max_threads
    """
    config = {
        "vt_api_key": os.getenv("VT_API_KEY", ""),
        "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "misp_url": os.getenv("MISP_URL", ""),
        "misp_api_key": os.getenv("MISP_API_KEY", ""),
        "misp_verify_cert": os.getenv("MISP_VERIFY_CERT", "false").lower() in ("true", "1", "yes"),
        "rate_limit_seconds": 1.0,
        "max_threads": 5,
    }

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                file_config = json.load(f)
                config.update(file_config)
        except (json.JSONDecodeError, OSError):
            pass  # ignore corrupt config

    return config

def save_config(
    vt_key=None,
    abuseipdb_key=None,
    misp_url=None,
    misp_key=None,
    misp_verify_cert=None,
    rate_limit=None,
    max_threads=None
):
    """
    Save configuration to file. Only non-None values are updated.
    """
    config = load_config()
    if vt_key is not None:
        config["vt_api_key"] = vt_key
    if abuseipdb_key is not None:
        config["abuseipdb_api_key"] = abuseipdb_key
    if misp_url is not None:
        config["misp_url"] = misp_url
    if misp_key is not None:
        config["misp_api_key"] = misp_key
    if misp_verify_cert is not None:
        config["misp_verify_cert"] = bool(misp_verify_cert)
    if rate_limit is not None:
        config["rate_limit_seconds"] = float(rate_limit)
    if max_threads is not None:
        config["max_threads"] = int(max_threads)

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, sort_keys=True)

    print(f"[+] Configuration saved to {CONFIG_FILE}")
