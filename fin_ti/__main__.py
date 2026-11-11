"""Command-line entry point:  python -m fin_ti <stage> [options]

Stages are added milestone by milestone; `run` chains all of them.
"""

from __future__ import annotations

import argparse
import json

from . import collect as collect_mod
from . import store


def cmd_collect(args: argparse.Namespace) -> None:
    feed, source = collect_mod.collect(offline=args.offline, refresh=args.refresh)
    vulns = feed["vulnerabilities"]
    print(f"Source:          {source}")
    print(f"Catalog version: {feed.get('catalogVersion', '?')}")
    print(f"Date released:   {feed.get('dateReleased', '?')}")
    print(f"Records:         {len(vulns)}")


def cmd_load(args: argparse.Namespace) -> None:
    """Collect (respecting --offline/--refresh) then upsert into SQLite."""
    feed, source = collect_mod.collect(offline=args.offline, refresh=args.refresh)
    with store.connect() as conn:
        stats = store.load(conn, feed, source)
        ransom = conn.execute("SELECT COUNT(*) FROM vulns WHERE ransomware=1").fetchone()[0]
        top = conn.execute(
            "SELECT vendor, COUNT(*) n FROM vulns GROUP BY vendor ORDER BY n DESC LIMIT 5"
        ).fetchall()
    print(f"Source: {source}")
    print(f"Loaded {stats['total']} records ({stats['new']} new, {stats['updated']} updated)")
    print(f"Known ransomware use: {ransom}")
    print("Top vendors: " + ", ".join(f"{r['vendor']} ({r['n']})" for r in top))


def print_evidence_check(check: dict[str, list[str]]) -> None:
    """Report watchlist citation verification (see score.verify_evidence)."""
    print(f"Watchlist evidence: {len(check['ok'])} verified, "
          f"{len(check['mismatch'])} mismatched, {len(check['not_loaded'])} not in loaded data")
    for m in check["mismatch"]:
        print(f"  MISMATCH {m}")


def cmd_score(args: argparse.Namespace) -> None:
    """Score everything already in SQLite (run `load` first)."""
    from . import score  # imported lazily so collect/load work without PyYAML

    with store.connect() as conn:
        ref = store.as_of(conn)
        watchlist = score.load_watchlist()
        n = score.score_all(conn, watchlist, ref)
        print_evidence_check(score.verify_evidence(conn, watchlist))
        rows = conn.execute(
            """SELECT v.cve_id, v.vendor, v.product, e.score, e.reasons
               FROM vulns v JOIN enrichment e USING (cve_id)
               ORDER BY e.score DESC, v.date_added DESC"""
        ).fetchall()
    bands: dict[str, int] = {}
    for r in rows:
        bands[score.priority(r["score"])] = bands.get(score.priority(r["score"]), 0) + 1
    print(f"Scored {n} records (recency reference date: {ref})")
    print("Priority bands: " + ", ".join(f"{b}={bands.get(b, 0)}" for b in ("P1", "P2", "P3", "P4")))
    print(f"\nTop {args.top}:")
    for r in rows[: args.top]:
        why = "; ".join(json.loads(r["reasons"]))
        print(f"  {r['score']:>3} {score.priority(r['score'])}  {r['cve_id']:<16} "
              f"{r['vendor']} {r['product']}\n         {why}")


def cmd_tag(args: argparse.Namespace) -> None:
    """ATT&CK-tag scored records and assign ICD 203 likelihood + confidence."""
    from . import score, tag

    with store.connect() as conn:
        n = tag.tag_all(conn, tag.load_rules())
        rows = conn.execute(
            """SELECT v.*, e.score, e.watch_hits, e.techniques, e.likelihood, e.confidence
               FROM vulns v JOIN enrichment e USING (cve_id)
               ORDER BY e.score DESC, v.date_added DESC"""
        ).fetchall()

    counts: dict[str, int] = {}
    for r in rows:
        for t in json.loads(r["techniques"]):
            key = f"{t['id']} {t['name']}"
            counts[key] = counts.get(key, 0) + 1
    tally = lambda col: ", ".join(
        f"{k}={v}" for k, v in sorted(
            {x: sum(1 for r in rows if r[col] == x) for x in {r[col] for r in rows}}.items(),
            key=lambda kv: -kv[1]))

    print(f"Tagged {n} records\n")
    print("Techniques:")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {v:>5}  {k}")
    print(f"\nLikelihood: {tally('likelihood')}")
    print(f"Confidence: {tally('confidence')}")
    print(f"\nQuestion: {tag.ESTIMATE_QUESTION}\n")
    for r in rows[: args.top]:
        hits, tags = json.loads(r["watch_hits"]), json.loads(r["techniques"])
        _, basis = tag.confidence(dict(r), hits, tags)
        print(f"[{score.priority(r['score'])}] " + tag.estimative_statement(
            r["cve_id"], r["vendor"], r["product"], r["score"], r["confidence"], basis))
        print("      ATT&CK: " + ", ".join(
            f"{t['id']} ({t['rule']} {t['basis']}: {t['matched']})" for t in tags) + "\n")


def cmd_report(args: argparse.Namespace) -> None:
    """Write output/tactical.md and output/brief.md from the enriched DB."""
    from . import report

    with store.connect() as conn:
        tactical, brief = report.write_reports(conn, store.as_of(conn), args.limit)
    print(f"Wrote {tactical}\nWrote {brief}")


def cmd_run(args: argparse.Namespace) -> None:
    """Whole pipeline: collect -> load -> score -> tag -> report, one line per stage."""
    from . import report, score, tag

    feed, source = collect_mod.collect(offline=args.offline, refresh=args.refresh)
    print(f"[1/5] collect  {len(feed['vulnerabilities'])} records from {source}")
    with store.connect() as conn:
        stats = store.load(conn, feed, source)
        print(f"[2/5] load     {stats['new']} new, {stats['updated']} updated")
        ref = store.as_of(conn)
        watchlist = score.load_watchlist()
        n = score.score_all(conn, watchlist, ref)
        print(f"[3/5] score    {n} records (as of {ref})")
        print("               ", end="")
        print_evidence_check(score.verify_evidence(conn, watchlist))
        tag.tag_all(conn, tag.load_rules())
        print("[4/5] tag      ATT&CK + ICD 203 likelihood/confidence")
        tactical, brief = report.write_reports(conn, ref, args.limit)
        print(f"[5/5] report   {tactical}\n               {brief}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="fin_ti", description=__doc__)
    sub = parser.add_subparsers(dest="stage", required=True)

    def add_stage(name: str, func, help_: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.add_argument("--offline", action="store_true", help="never hit the network")
        p.add_argument("--refresh", action="store_true", help="force a fresh download")
        p.set_defaults(func=func)
        return p

    add_stage("collect", cmd_collect, "download or load the cached KEV feed")
    add_stage("load", cmd_load, "collect, normalize and upsert into SQLite")

    p = sub.add_parser("score", help="score stored records against the watchlist")
    p.add_argument("--top", type=int, default=10, help="how many top items to print")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("tag", help="ATT&CK tags + ICD 203 likelihood/confidence")
    p.add_argument("--top", type=int, default=5, help="how many example statements to print")
    p.set_defaults(func=cmd_tag)

    p = sub.add_parser("report", help="write tactical.md and brief.md")
    p.add_argument("--limit", type=int, default=100, help="max rows in the tactical table")
    p.set_defaults(func=cmd_report)

    p = add_stage("run", cmd_run, "run the whole pipeline end to end")
    p.add_argument("--limit", type=int, default=100, help="max rows in the tactical table")

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
