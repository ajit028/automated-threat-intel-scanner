"""
Cache Module
============
SQLite-based caching for threat intelligence lookups to prevent rate limiting.
Thread-safe with WAL journal mode and busy timeout handling for high-throughput scanning.
"""

import sqlite3
import datetime
import json
import os
import threading

DB_FILE = os.environ.get("CACHE_DB_PATH", "scan_cache.db")
_db_lock = threading.Lock()


def get_connection(timeout: float = 30.0) -> sqlite3.Connection:
    """Create a connection with timeout and WAL journal mode."""
    conn = sqlite3.connect(DB_FILE, timeout=timeout)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db():
    """Initialize the cache database."""
    with _db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    data TEXT,
                    timestamp DATETIME
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Error initializing cache DB: {e}")


def get_cached_result(ioc: str):
    """Retrieve cached result if exists and < 24h old."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=24)
        cursor.execute("SELECT data FROM cache WHERE ioc = ? AND timestamp > ?", (ioc, cutoff))
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        print(f"[-] Error reading cache: {e}")
    return None


def set_cached_result(ioc: str, ioc_type: str, data: dict):
    """Cache the result safely with thread locking."""
    init_db()
    with _db_lock:
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO cache (ioc, ioc_type, data, timestamp) VALUES (?, ?, ?, ?)",
                (ioc, ioc_type, json.dumps(data), datetime.datetime.utcnow())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Error writing cache: {e}")
