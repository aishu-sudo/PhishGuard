"""
Correlation Database
----------------------
SQLite persistence for Stage 2/3 findings — domains discovered per
investigation, their fingerprints, and cluster-level reports. This is
what lets clustering accumulate across multiple investigated URLs
over time, instead of each run starting from nothing.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from app.config import BASE_DIR

DB_PATH = BASE_DIR / "Backend" / "app" / "data" / "correlation.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            source TEXT NOT NULL,          -- e.g. 'user_input', 'crt.sh', 'reverse_ip'
            cluster_id INTEGER,
            first_seen TEXT NOT NULL,
            UNIQUE(domain, source)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            favicon_hash TEXT,
            html_hash TEXT,
            js_hash TEXT,
            checked_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            cluster_id INTEGER PRIMARY KEY,
            risk TEXT,
            domain_count INTEGER,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_domain(domain, source, cluster_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO domains (domain, source, cluster_id, first_seen)
        VALUES (?, ?, ?, ?)
    """, (domain, source, cluster_id, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


def save_domains_bulk(domains, source, cluster_id=None):
    """Save many discovered domains from one source (e.g. crt.sh results) at once."""
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cur.executemany("""
        INSERT OR IGNORE INTO domains (domain, source, cluster_id, first_seen)
        VALUES (?, ?, ?, ?)
    """, [(d, source, cluster_id, now) for d in domains])
    conn.commit()
    conn.close()


def get_domains_by_cluster(cluster_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM domains WHERE cluster_id = ?", (cluster_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def find_existing_cluster_for_domain(domain):
    """Check if this domain (or one related to it) is already part of a known cluster."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT cluster_id FROM domains WHERE domain = ? AND cluster_id IS NOT NULL", (domain,))
    row = cur.fetchone()
    conn.close()
    return row["cluster_id"] if row else None


def get_next_cluster_id():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT MAX(cluster_id) as max_id FROM domains")
    row = cur.fetchone()
    conn.close()
    max_id = row["max_id"] if row and row["max_id"] is not None else 0
    return max_id + 1