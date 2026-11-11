"""Stage 3 - Score each KEV entry for relevance to financial institutions.

The score (0-100) is a transparent sum; every point comes with a reason string
so an analyst can defend any ranking line-by-line:

    watchlist product match   +weight (15-40, from config/watchlist.yaml)
    watchlist vendor only     +vendor_only_points (10)
    internet-facing product   +internet_facing_points (15)
    known ransomware use      +25   (CISA 'knownRansomwareCampaignUse')
    added to KEV <= 30 days   +20   (relative to feed release date)
    added to KEV <= 90 days   +10

Priority bands: P1 >= 70, P2 >= 45, P3 >= 25, else P4.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from . import CONFIG_DIR

RANSOMWARE_POINTS = 25
RECENT_30_POINTS = 20
RECENT_90_POINTS = 10
PRIORITY_BANDS = [(70, "P1"), (45, "P2"), (25, "P3"), (0, "P4")]


def load_watchlist(path: Path = CONFIG_DIR / "watchlist.yaml") -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def word_match(keyword: str, text: str) -> bool:
    """Case-insensitive whole-word match, so 'ISE' doesn't hit 'Enterprise'
    and 'SAP' doesn't hit 'Sapido'."""
    return re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", text, re.IGNORECASE) is not None


def match_watchlist(vendor: str, product: str, watchlist: dict) -> list[dict]:
    """Return all watchlist hits for a record, strongest first.

    level='product' when vendor and a listed product keyword both match,
    level='vendor' when only the vendor matches."""
    hits = []
    for e in watchlist["entries"]:
        if not word_match(e["vendor"], vendor):
            continue
        product_hit = any(word_match(k, product) for k in e.get("products", []))
        hits.append({
            "id": e["id"],
            "level": "product" if product_hit else "vendor",
            "category": e["category"],
            "internet_facing": bool(e.get("internet_facing")) and product_hit,
            "points": e["weight"] if product_hit else watchlist["vendor_only_points"],
            "rationale": e["rationale"],
        })
    # Product hits beat vendor-only hits; then by points.
    return sorted(hits, key=lambda h: (h["level"] == "product", h["points"]), reverse=True)


def priority(score: int) -> str:
    return next(label for floor, label in PRIORITY_BANDS if score >= floor)


def score_record(rec: dict, watchlist: dict, as_of: str) -> tuple[int, list[str], list[dict]]:
    """Pure function: (score, reasons, watchlist_hits) for one normalized record."""
    reasons: list[str] = []
    score = 0

    hits = match_watchlist(rec["vendor"], rec["product"], watchlist)
    if hits:
        best = hits[0]  # count only the strongest hit, so overlaps don't double-count
        score += best["points"]
        what = "product" if best["level"] == "product" else "vendor only"
        reasons.append(f"+{best['points']} watchlist {what}: {best['id']}")
        if best["internet_facing"]:
            pts = watchlist["internet_facing_points"]
            score += pts
            reasons.append(f"+{pts} internet-facing ({best['category']})")

    if rec["ransomware"]:
        score += RANSOMWARE_POINTS
        reasons.append(f"+{RANSOMWARE_POINTS} known ransomware use (CISA)")

    if as_of and rec["date_added"]:
        age = (date.fromisoformat(as_of) - date.fromisoformat(rec["date_added"])).days
        if age <= 30:
            score += RECENT_30_POINTS
            reasons.append(f"+{RECENT_30_POINTS} added to KEV {age}d before feed date")
        elif age <= 90:
            score += RECENT_90_POINTS
            reasons.append(f"+{RECENT_90_POINTS} added to KEV {age}d before feed date")

    return min(score, 100), reasons, hits


def score_all(conn: sqlite3.Connection, watchlist: dict, as_of: str) -> int:
    """Score every row in `vulns` and upsert the score columns of `enrichment`."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []
    for rec in conn.execute("SELECT * FROM vulns"):
        s, reasons, hits = score_record(dict(rec), watchlist, as_of)
        rows.append((rec["cve_id"], s, json.dumps(reasons), json.dumps(hits), now))
    with conn:
        conn.executemany(
            """
            INSERT INTO enrichment (cve_id, score, reasons, watch_hits, scored_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,
                reasons=excluded.reasons, watch_hits=excluded.watch_hits,
                scored_at=excluded.scored_at
            """,
            rows,
        )
    return len(rows)


def verify_evidence(conn: sqlite3.Connection, watchlist: dict) -> dict[str, list[str]]:
    """Check every `kev:CVE-...` citation in the watchlist against the loaded data.

    A small citation-verification step: a cited CVE must exist in the KEV data
    AND match its own watchlist entry at product level. That catches typos,
    wrong-product citations, and matching gaps (it found Log4j vs Log4j2).

    Returns {"ok": [...], "mismatch": [...], "not_loaded": [...]}. "not_loaded"
    is expected when running on the small bundled sample."""
    out: dict[str, list[str]] = {"ok": [], "mismatch": [], "not_loaded": []}
    for e in watchlist["entries"]:
        for ref in e.get("evidence", []):
            cve = ref.removeprefix("kev:")
            row = conn.execute(
                "SELECT vendor, product FROM vulns WHERE cve_id = ?", (cve,)
            ).fetchone()
            if row is None:
                out["not_loaded"].append(f"{e['id']}: {cve}")
                continue
            hits = match_watchlist(row["vendor"], row["product"], watchlist)
            if any(h["id"] == e["id"] and h["level"] == "product" for h in hits):
                out["ok"].append(f"{e['id']}: {cve}")
            else:
                out["mismatch"].append(
                    f"{e['id']}: {cve} is '{row['vendor']} | {row['product']}', "
                    f"which does not match this entry at product level")
    return out
