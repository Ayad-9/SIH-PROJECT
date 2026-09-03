"""
AE-Forensics: Database Layer (SQLite)
Embedded SQLite storage preserving raw MIME structures, parsed artifacts,
relational hops, and immutable SHA-256 fingerprints for court admissibility.
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

def get_default_db_path() -> str:
    return os.environ.get("AE_DB_PATH", "forensics.db")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Establish an SQLite connection configured with WAL mode and ensure tables exist.
    """
    target_path = db_path or get_default_db_path()
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    
    # Auto-initialize tables idempotently
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY,
        sha256 TEXT UNIQUE NOT NULL,
        subject TEXT,
        sender TEXT,
        sender_domain TEXT,
        return_path TEXT,
        recipient TEXT,
        received_date TEXT,
        origin_ip TEXT,
        threat_score REAL,
        verdict TEXT,
        spf_status TEXT,
        dkim_status TEXT,
        dmarc_status TEXT,
        nlp_score REAL,
        raw_headers TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hops (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        hop_order INTEGER,
        relay_ip TEXT,
        is_private INTEGER,
        claimed_host TEXT,
        city TEXT,
        country TEXT,
        latitude REAL,
        longitude REAL,
        FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Explicitly ensure tables and indexes exist.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_sha256 ON cases(sha256);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);")
    conn.commit()
    conn.close()


def save_case(case_data: Dict[str, Any], hops: List[Dict[str, Any]], db_path: Optional[str] = None) -> str:
    """
    Persist an ingested email case and its sequential transmission hops.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    now_iso = datetime.now(timezone.utc).isoformat()

    cur.execute("""
        INSERT OR REPLACE INTO cases (
            case_id, sha256, subject, sender, sender_domain, return_path,
            recipient, received_date, origin_ip, threat_score, verdict,
            spf_status, dkim_status, dmarc_status, nlp_score, raw_headers, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        case_data.get("case_id"),
        case_data.get("sha256"),
        case_data.get("subject", "No Subject"),
        case_data.get("sender", "Unknown"),
        case_data.get("sender_domain", "unknown"),
        case_data.get("return_path", "None"),
        case_data.get("recipient", "None"),
        case_data.get("received_date", now_iso),
        case_data.get("origin_ip", "0.0.0.0"),
        case_data.get("threat_score", 0.0),
        case_data.get("verdict", "CLEAN"),
        case_data.get("spf_status", "NONE"),
        case_data.get("dkim_status", "NONE"),
        case_data.get("dmarc_status", "NONE"),
        case_data.get("nlp_score", 0.0),
        case_data.get("raw_headers", ""),
        now_iso
    ))

    # Remove existing hops for idempotency if replacing
    cur.execute("DELETE FROM hops WHERE case_id = ?", (case_data.get("case_id"),))

    for hop in hops:
        cur.execute("""
            INSERT INTO hops (
                case_id, hop_order, relay_ip, is_private,
                claimed_host, city, country, latitude, longitude
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_data.get("case_id"),
            hop.get("hop_order", 0),
            hop.get("relay_ip", "0.0.0.0"),
            1 if hop.get("is_private") else 0,
            hop.get("claimed_host", "Unknown"),
            hop.get("city", "Unknown"),
            hop.get("country", "Unknown"),
            float(hop.get("latitude", 0.0)),
            float(hop.get("longitude", 0.0))
        ))

    conn.commit()
    conn.close()
    return case_data.get("case_id")


def get_cases(limit: int = 50, offset: int = 0, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieve historical triage records ordered by most recent.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT case_id, sha256, subject, sender, sender_domain, recipient,
               received_date, origin_ip, threat_score, verdict,
               spf_status, dkim_status, dmarc_status, nlp_score, created_at
        FROM cases
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cur.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results


def get_case_by_id(case_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve single case record including full header text and sequential hops.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    case = dict(row)
    cur.execute("""
        SELECT id, hop_order, relay_ip, is_private, claimed_host, city, country, latitude, longitude
        FROM hops
        WHERE case_id = ?
        ORDER BY hop_order ASC
    """, (case_id,))
    case["hops"] = [dict(h) for h in cur.fetchall()]
    conn.close()
    return case


def get_case_by_hash(sha256_hash: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Lookup existing case by SHA-256 evidence fingerprint.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT case_id FROM cases WHERE sha256 = ?", (sha256_hash,))
    row = cur.fetchone()
    conn.close()
    if row:
        return get_case_by_id(row["case_id"], db_path)
    return None


def delete_case(case_id: str, db_path: Optional[str] = None) -> bool:
    """
    Delete a case and its cascade hops.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def get_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Aggregate metrics for the SOC analyst dashboard header.
    """
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as total FROM cases")
    total = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) as malicious FROM cases WHERE verdict = 'MALICIOUS'")
    malicious = cur.fetchone()["malicious"]
    cur.execute("SELECT COUNT(*) as suspicious FROM cases WHERE verdict = 'SUSPICIOUS'")
    suspicious = cur.fetchone()["suspicious"]
    cur.execute("SELECT COUNT(*) as clean FROM cases WHERE verdict = 'CLEAN'")
    clean = cur.fetchone()["clean"]
    cur.execute("SELECT AVG(threat_score) as avg_score FROM cases")
    avg_score = cur.fetchone()["avg_score"] or 0.0
    conn.close()
    return {
        "total_analyzed": total,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "clean_count": clean,
        "avg_threat_score": round(avg_score, 1)
    }
