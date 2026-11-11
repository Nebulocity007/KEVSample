"""Stage 2 - Normalize KEV records and store them in SQLite.

Tables
* vulns       one row per CVE, normalized from the KEV feed (upserted each run)
* feed_runs   one row per load: catalog version, source, record count
              (the audit trail / basis for trend analysis later)
* enrichment  our analytic layer: score, ATT&CK tags, ICD 203 estimate.
              Kept separate from source data so facts and judgments never mix.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulns (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL,
    name            TEXT,
    description     TEXT,
    required_action TEXT,
    date_added      TEXT,              -- ISO date CISA added it to KEV
    due_date        TEXT,              -- FCEB remediation deadline (BOD 22-01)
    ransomware      INTEGER NOT NULL,  -- 1 = CISA says 'Known' ransomware use
    cwes            TEXT NOT NULL,     -- JSON list, e.g. ["CWE-77"]
    notes           TEXT,              -- CISA notes; usually vendor advisory URLs
    first_seen      TEXT NOT NULL,     -- when *this pipeline* first saw it
    last_seen       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feed_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    catalog_version TEXT,
    date_released   TEXT,
    source          TEXT,
    record_count    INTEGER
);
CREATE TABLE IF NOT EXISTS enrichment (
    cve_id      TEXT PRIMARY KEY REFERENCES vulns(cve_id),
    score       INTEGER,
    reasons     TEXT,   -- JSON list of human-readable scoring reasons
    watch_hits  TEXT,   -- JSON list of matched watchlist entries
    techniques  TEXT,   -- JSON list of {id, name, rule, rationale}
    likelihood  TEXT,   -- ICD 203 estimative term
    confidence  TEXT,   -- low / moderate / high
    scored_at   TEXT
);
"""


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    conn.executescript(SCHEMA)
    return conn


def normalize(rec: dict) -> dict:
    """Map one raw KEV record to our column names, cleaning whitespace and types."""
    clean = lambda k: (rec.get(k) or "").strip()
    return {
        "cve_id": clean("cveID").upper(),
        "vendor": clean("vendorProject"),
        "product": clean("product"),
        "name": clean("vulnerabilityName"),
        "description": clean("shortDescription"),
        "required_action": clean("requiredAction"),
        "date_added": clean("dateAdded"),
        "due_date": clean("dueDate"),
        "ransomware": int(clean("knownRansomwareCampaignUse").lower() == "known"),
        "cwes": json.dumps(sorted(set(rec.get("cwes") or []))),
        "notes": clean("notes"),
    }


def load(conn: sqlite3.Connection, feed: dict, source: str) -> dict:
    """Upsert every record; returns counts of new vs. already-known CVEs."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    before = {r[0] for r in conn.execute("SELECT cve_id FROM vulns")}
    rows = [normalize(r) for r in feed["vulnerabilities"]]
    with conn:  # one transaction
        conn.executemany(
            """
            INSERT INTO vulns VALUES (
                :cve_id, :vendor, :product, :name, :description, :required_action,
                :date_added, :due_date, :ransomware, :cwes, :notes, :now, :now)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor=excluded.vendor, product=excluded.product, name=excluded.name,
                description=excluded.description, required_action=excluded.required_action,
                date_added=excluded.date_added, due_date=excluded.due_date,
                ransomware=excluded.ransomware, cwes=excluded.cwes, notes=excluded.notes,
                last_seen=excluded.last_seen  -- first_seen is deliberately preserved
            """,
            [{**r, "now": now} for r in rows],
        )
        conn.execute(
            "INSERT INTO feed_runs (run_at, catalog_version, date_released, source,"
            " record_count) VALUES (?, ?, ?, ?, ?)",
            (now, feed.get("catalogVersion"), feed.get("dateReleased"), source, len(rows)),
        )
    new = sum(1 for r in rows if r["cve_id"] not in before)
    return {"total": len(rows), "new": new, "updated": len(rows) - new}


def as_of(conn: sqlite3.Connection) -> str:
    """Reference date for 'recency' = the feed's release date, not wall-clock.

    Using the feed date keeps offline/sample demos reproducible."""
    row = conn.execute(
        "SELECT date_released FROM feed_runs ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    return (row[0] or "")[:10] if row else ""
