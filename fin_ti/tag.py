"""Stage 4 - ATT&CK tagging and ICD 203 estimative language.

Two separate judgments, as ICD 203 requires:

1. LIKELIHOOD (how probable), using the ICD 203 seven-term scale. The question
   being estimated is fixed and stated in every output:

       "How likely is it that threat actors will attempt to exploit this
        vulnerability against financial-sector organizations in the next 90 days?"

   It is derived from the relevance score. The scale is deliberately capped at
   "very likely": a rules engine with no sector telemetry should not claim
   "almost certain".

2. CONFIDENCE (how solid the basis is), from three independent evidence points:
     a) product-level watchlist match (not just the vendor)
     b) CISA reports known ransomware use
     c) at least one ATT&CK tag grounded in the record's own text (CWE/keyword)
   3 points = high, 2 = moderate, 0-1 = low.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import yaml

from . import CONFIG_DIR
from .score import word_match

ESTIMATE_QUESTION = (
    "How likely is it that threat actors will attempt to exploit this vulnerability "
    "against financial-sector organizations in the next 90 days?"
)

# ICD 203 terms with their probability ranges, highest first.
# (score floor, term, range). "almost certain (95-99%)" is intentionally unreachable.
LIKELIHOOD_BANDS = [
    (80, "very likely", "80-95%"),
    (65, "likely", "55-80%"),
    (45, "roughly even chance", "45-55%"),
    (25, "unlikely", "20-45%"),
    (10, "very unlikely", "05-20%"),
    (0, "almost no chance", "01-05%"),
]

EVIDENCE_CONDITIONS = {"cwes", "keywords"}  # everything else is inference


def load_rules(path: Path = CONFIG_DIR / "attack_rules.yaml") -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["rules"]


def tag_record(rec: dict, hits: list[dict], rules: list[dict]) -> list[dict]:
    """Return ATT&CK tags for one record, with which condition fired and its basis."""
    text = f"{rec['name']} {rec['description']}"
    vp = f"{rec['vendor']} {rec['product']}"
    cwes = set(json.loads(rec["cwes"]))
    best = hits[0] if hits else {}

    tags = []
    for r in rules:
        w = r["when"]
        # Each check returns a short label of what matched, or None.
        # Evidence checks come first so they win when several conditions match.
        checks = {
            "cwes": next((c for c in w.get("cwes", []) if c in cwes), None),
            "keywords": next((k for k in w.get("keywords", []) if word_match(k, text)), None),
            "products": next((p for p in w.get("products", []) if word_match(p, vp)), None),
            "categories": best.get("category") if best.get("level") == "product"
                          and best.get("category") in w.get("categories", []) else None,
            "internet_facing": "watchlist" if w.get("internet_facing")
                               and best.get("internet_facing") else None,
            "ransomware": "CISA" if w.get("ransomware") and rec["ransomware"] else None,
        }
        fired = [(cond, val) for cond, val in checks.items() if val]
        if not fired:
            continue
        cond, val = fired[0]
        tags.append({
            "id": r["technique"], "name": r["name"], "tactic": r["tactic"],
            "rule": r["id"], "matched": f"{cond}={val}",
            "basis": "evidence" if cond in EVIDENCE_CONDITIONS else "inference",
            "rationale": r["rationale"],
        })
    return tags


def likelihood(score: int) -> tuple[str, str]:
    """Map a 0-100 relevance score to an ICD 203 (term, probability range)."""
    return next((term, rng) for floor, term, rng in LIKELIHOOD_BANDS if score >= floor)


def confidence(rec: dict, hits: list[dict], tags: list[dict]) -> tuple[str, list[str]]:
    """Return (level, basis) where basis lists which evidence points were present."""
    basis = []
    if hits and hits[0]["level"] == "product":
        basis.append("product-level watchlist match")
    if rec["ransomware"]:
        basis.append("CISA-reported ransomware use")
    if any(t["basis"] == "evidence" for t in tags):
        basis.append("technique grounded in CVE text")
    level = {3: "high", 2: "moderate"}.get(len(basis), "low")
    return level, basis


def estimative_statement(cve: str, vendor: str, product: str, score: int,
                         conf: str, basis: list[str]) -> str:
    """One analyst-style sentence in ICD 203 form: likelihood term + range + confidence."""
    term, rng = likelihood(score)
    why = "; ".join(basis) if basis else "limited corroborating attributes"
    return (f"We assess it is {term} ({rng}) that threat actors will attempt to exploit "
            f"{cve} ({vendor} {product}) against financial-sector organizations within "
            f"90 days ({conf} confidence: {why}).")


def tag_all(conn: sqlite3.Connection, rules: list[dict]) -> int:
    """Tag every scored record; writes techniques/likelihood/confidence to enrichment."""
    rows = conn.execute(
        "SELECT v.*, e.score, e.watch_hits FROM vulns v JOIN enrichment e USING (cve_id)"
    ).fetchall()
    if not rows:
        raise RuntimeError("No scored records. Run `python -m fin_ti score` first.")
    updates = []
    for row in rows:
        rec, hits = dict(row), json.loads(row["watch_hits"])
        tags = tag_record(rec, hits, rules)
        conf, _ = confidence(rec, hits, tags)
        updates.append((json.dumps(tags), likelihood(rec["score"])[0], conf, rec["cve_id"]))
    with conn:
        conn.executemany(
            "UPDATE enrichment SET techniques=?, likelihood=?, confidence=? WHERE cve_id=?",
            updates,
        )
    return len(updates)
