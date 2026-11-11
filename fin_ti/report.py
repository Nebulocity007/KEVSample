"""Stage 5 - Render Markdown outputs from the enriched SQLite data.

* tactical.md - sortable triage table for SOC / vulnerability-management teams
* brief.md    - one-page executive brief for a CISO (BLUF, key judgments in
                ICD 203 language, top actions, trend, method)

Everything is computed from the DB; there is no free-text generation, so every
number in the brief can be traced back to a query.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import date
from pathlib import Path

from . import OUTPUT_DIR
from .score import priority
from .tag import ESTIMATE_QUESTION, likelihood

NVD = "https://nvd.nist.gov/vuln/detail/{}"
KEV_HOME = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EDGE_CATEGORIES = {"edge", "email", "file-transfer", "remote-mgmt"}


# --------------------------------------------------------------------------- data
def fetch(conn: sqlite3.Connection) -> list[dict]:
    """All enriched records, best first, with JSON columns decoded."""
    rows = conn.execute(
        """SELECT v.*, e.score, e.reasons, e.watch_hits, e.techniques,
                  e.likelihood, e.confidence
           FROM vulns v JOIN enrichment e USING (cve_id)
           WHERE e.techniques IS NOT NULL
           ORDER BY e.score DESC, v.date_added DESC, v.cve_id"""
    ).fetchall()
    if not rows:
        raise RuntimeError("No tagged records. Run `python -m fin_ti tag` first.")
    out = []
    for r in rows:
        d = dict(r)
        for col in ("reasons", "watch_hits", "techniques", "cwes"):
            d[col] = json.loads(d[col] or "[]")
        d["priority"] = priority(d["score"])
        d["category"] = d["watch_hits"][0]["category"] if d["watch_hits"] and \
            d["watch_hits"][0]["level"] == "product" else ""
        out.append(d)
    return out


def feed_meta(conn: sqlite3.Connection) -> dict:
    row = conn.execute("SELECT * FROM feed_runs ORDER BY run_id DESC LIMIT 1").fetchone()
    return dict(row) if row else {}


def age_days(rec: dict, as_of: date) -> int:
    return (as_of - date.fromisoformat(rec["date_added"])).days


def md(text: str) -> str:
    """Escape characters that would break a Markdown table cell."""
    return (text or "").replace("|", "\\|").replace("\n", " ")


# ----------------------------------------------------------------------- tactical
def render_tactical(recs: list[dict], meta: dict, as_of: date, limit: int) -> str:
    shown = [r for r in recs if r["priority"] in ("P1", "P2")][:limit]
    hidden = sum(1 for r in recs if r["priority"] in ("P1", "P2")) - len(shown)
    lines = [
        "# Tactical Table: CISA KEV x Financial-Sector Watchlist",
        "",
        f"**TLP:CLEAR** (public sources only) | KEV catalog `{meta.get('catalog_version')}` "
        f"| as of {as_of} | source: {meta.get('source')}",
        "",
        f"Estimative question: *{ESTIMATE_QUESTION}*",
        "",
        "Score = analyst-curated watchlist weight + internet-facing + ransomware + recency "
        "(see README; watchlist not yet validated against member inventories). "
        "ATT&CK tags marked `*` are grounded in the CVE text; others are inferred from context.",
        "",
        "| Pri | Score | CVE | Vendor / Product | KEV added | Ransomware | ATT&CK | "
        "Likelihood | Confidence | Why |",
        "|---|---:|---|---|---|:-:|---|---|---|---|",
    ]
    for r in shown:
        attack = ", ".join(t["id"] + ("*" if t["basis"] == "evidence" else "")
                           for t in r["techniques"]) or "-"
        why = "; ".join(x.split(" ", 1)[1] for x in r["reasons"])  # drop "+N"
        lines.append(
            f"| {r['priority']} | {r['score']} | [{r['cve_id']}]({NVD.format(r['cve_id'])}) "
            f"| {md(r['vendor'])} / {md(r['product'])} | {r['date_added']} "
            f"| {'Yes' if r['ransomware'] else ''} | {attack} | {r['likelihood']} "
            f"| {r['confidence']} | {md(why)} |"
        )
    counts = Counter(r["priority"] for r in recs)
    lines += [
        "",
        f"Showing {len(shown)} P1/P2 items"
        + (f" ({hidden} more P1/P2 omitted; raise `--limit`)" if hidden else "")
        + f". Totals: P1={counts['P1']}, P2={counts['P2']}, P3={counts['P3']}, "
          f"P4={counts['P4']}.",
        "",
        "Required action for every row is CISA's KEV `requiredAction` (apply vendor "
        "mitigations or discontinue use). Vendor advisory links are in the DB `notes` column.",
    ]
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------------- brief
# The brief judges categories of vulnerability, so its question differs from the
# per-CVE question used in the tactical table.
BRIEF_QUESTION = (
    "How likely is it that threat actors will attempt to exploit this category of "
    "vulnerability against financial-sector organizations in the next 90 days?"
)
CONF_ORDER = {"low": 0, "moderate": 1, "high": 2}


def key_judgment(label: str, group: list[dict], claim: str,
                 max_confidence: str | None = None, note: str = "") -> str:
    """One ICD 203 key judgment about a group (category) of CVEs.

    Likelihood and confidence come from the group's strongest member (highest
    score, ties broken by confidence), so the judgment never overstates the data.
    `max_confidence` caps confidence when the analyst knows the basis is weaker
    than the per-CVE rule suggests (e.g. every attribute comes from one source)."""
    lead = max(group, key=lambda r: (r["score"], CONF_ORDER[r["confidence"]]))
    term, rng = likelihood(lead["score"])
    conf = lead["confidence"]
    if max_confidence and CONF_ORDER[conf] > CONF_ORDER[max_confidence]:
        conf = max_confidence
    note = f"; {note}" if note else ""
    return (f"- **{label}.** We assess it is **{term}** ({rng}) that {claim} "
            f"(*{conf} confidence*{note}; e.g. {lead['cve_id']}, "
            f"{lead['vendor']} {lead['product']}).")


def group_by_product(items: list[dict]) -> list[tuple[str, list[dict]]]:
    """Group already-ranked items by vendor+product, keeping rank order of first appearance."""
    groups: dict[str, list[dict]] = {}
    for r in items:
        groups.setdefault(f"{r['vendor']} {r['product']}", []).append(r)
    return list(groups.items())


def render_brief(recs: list[dict], meta: dict, as_of: date) -> str:
    recent90 = [r for r in recs if age_days(r, as_of) <= 90]
    recent30 = [r for r in recent90 if age_days(r, as_of) <= 30]
    fs90 = [r for r in recent90 if r["watch_hits"] and r["watch_hits"][0]["level"] == "product"]
    edge90 = [r for r in fs90 if r["category"] in EDGE_CATEGORIES]
    ransom = [r for r in recs if r["ransomware"] and r["category"]]
    # Replaces an uncited "dominant initial-access route" claim with a number
    # computed from our own data.
    ransom_edge = [r for r in ransom if r["category"] in EDGE_CATEGORIES]
    endpoint90 = [r for r in fs90 if r["category"] == "endpoint"]
    # Tie-break rule (stated in the brief): score desc, then most recent KEV
    # addition, then CVE ID, so the ranking is fully deterministic.
    top5 = sorted(fs90 or recent90,
                  key=lambda r: (-r["score"], age_days(r, as_of), r["cve_id"]))[:5]

    # KEV additions per 30-day period (inclusive day ranges, matching the labels).
    windows = []
    for lo, hi, label in ((0, 30, "last 30 days"), (31, 60, "31-60 days"),
                          (61, 90, "61-90 days")):
        in_win = [r for r in recs if lo <= age_days(r, as_of) <= hi]
        fs = sum(1 for r in in_win if r["category"])
        windows.append(f"{label}: {len(in_win)} added ({fs} watchlist products)")
    vendors = Counter(r["vendor"] for r in recent90).most_common(4)

    L = [
        "# Executive Brief: Known Exploited Vulnerabilities and the Financial Sector",
        "",
        f"**TLP:CLEAR** | as of {as_of} | CISA KEV catalog `{meta.get('catalog_version')}` "
        f"| Audience: CISO",
        "",
        "## Bottom Line Up Front",
        f"CISA added **{len(recent90)}** actively exploited vulnerabilities to KEV in the last "
        f"90 days ({len(recent30)} in the last 30). **{len(fs90)}** affect technologies on an "
        f"analyst-curated financial-sector watchlist (not yet validated against member "
        f"inventories), **{len(edge90)}** of them internet-facing edge, email, file-transfer or "
        f"remote-management products. In KEV data, those categories account for "
        f"**{len(ransom_edge)} of {len(ransom)}** ransomware-linked watchlist KEVs (all-time). "
        f"Patch or mitigate the Top 5 below first.",
        "",
        "*Caveat: KEV shows exploitation, not targeting. Inclusion means a flaw was exploited "
        "somewhere, not that financial institutions were the targets.*",
        "",
        "## Key Judgments",
        f"*Question: {BRIEF_QUESTION}*",
        "",
    ]
    if edge90:
        L.append(key_judgment(
            "Edge exposure", edge90,
            "threat actors will attempt to exploit recently added edge/remote-access KEVs "
            "against financial institutions within 90 days"))
    if ransom:
        L.append(key_judgment(
            "Ransomware", ransom,
            f"ransomware operators will continue to use the {len(ransom)} ransomware-linked "
            f"KEVs in watchlist products (all-time, since KEV began in 2021) for initial access",
            max_confidence="moderate",
            note="ransomware use, product and exploitation attributes all come from a "
                 "single source (CISA KEV)"))
    if endpoint90:
        L.append(key_judgment(
            "Endpoints", endpoint90,
            "threat actors will attempt to exploit recently added browser, Office or Windows "
            "KEVs against financial-sector staff"))
    L += [
        "",
        "## Top 5 Actions (added to KEV in last 90 days), grouped by product",
        "*Ranking: highest score first; ties broken by most recent KEV addition, then CVE ID.*",
        "",
        "| # | Product | CVEs (score, likelihood / confidence) | ATT&CK |",
        "|---|---|---|---|",
    ]
    for i, (product, items) in enumerate(group_by_product(top5), 1):
        cves = "; ".join(f"[{r['cve_id']}]({NVD.format(r['cve_id'])}) "
                         f"({r['score']}, {r['likelihood']} / {r['confidence']})" for r in items)
        # Union of techniques across the group, in first-seen order.
        attack = ", ".join(dict.fromkeys(t["id"] for r in items for t in r["techniques"])) or "-"
        L.append(f"| {i} | {md(product)} | {cves} | {attack} |")
    L += [
        "",
        "## Trend",
        "- KEV additions: " + "; ".join(windows) + ".",
        "- Most-added vendors (90d): " + ", ".join(f"{v} ({n})" for v, n in vendors) + ".",
        "- *Caveat: three 30-day periods are not a trend; read these as a snapshot, "
        "not a direction.*",
        "",
        "## Recommended Actions",
        "1. **Patch / mitigate** the Top 5 within 72 hours; if not possible, remove from "
        "internet exposure or enable vendor mitigations.",
        "2. **Hunt** for prior exploitation on edge devices (T1190/T1133): review VPN/ADC logs, "
        "integrity-check appliances, and rotate sessions and credentials where vendors advise.",
        "3. **Reconcile** this watchlist with the asset inventory; any KEV product we run but "
        "don't track is a blind spot.",
        "4. **Share** observed exploitation indicators with FS-ISAC to raise sector confidence.",
        "",
        "## Method and Confidence",
        f"Source: [CISA KEV]({KEV_HOME}) (public). Relevance is scored by transparent rules "
        "(watchlist match, internet exposure, ransomware use, recency); ATT&CK techniques are "
        "rule-mapped. Likelihood uses ICD 203 terms and is capped at \"very likely\". "
        "Confidence reflects the number of corroborating attributes. The watchlist's product "
        "choices and weights are analyst judgment; each entry cites KEV CVEs showing the "
        "product is exploited, but none shows how widely financial institutions run it. "
        "KEV confirms "
        "exploitation *somewhere*; it does not confirm targeting of financial institutions, "
        "so no judgment here is rated above what the source supports.",
    ]
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------- driver
def write_reports(conn: sqlite3.Connection, as_of_str: str, limit: int = 100,
                  out_dir: Path = OUTPUT_DIR) -> tuple[Path, Path]:
    recs, meta = fetch(conn), feed_meta(conn)
    as_of = date.fromisoformat(as_of_str) if as_of_str else date.today()
    out_dir.mkdir(parents=True, exist_ok=True)
    tactical, brief = out_dir / "tactical.md", out_dir / "brief.md"
    tactical.write_text(render_tactical(recs, meta, as_of, limit), encoding="utf-8")
    brief.write_text(render_brief(recs, meta, as_of), encoding="utf-8")
    return tactical, brief
