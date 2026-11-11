"""Score-stage tests: pure functions over hand-built records."""

import tempfile
import unittest
from pathlib import Path

from fin_ti import collect, score, store

WL = score.load_watchlist()


def rec(vendor, product, ransomware=0, added="2020-01-01"):
    return {"vendor": vendor, "product": product, "ransomware": ransomware, "date_added": added}


class ScoreTests(unittest.TestCase):
    def test_citrix_bleed_is_p1(self):
        s, reasons, hits = score.score_record(
            rec("Citrix", "NetScaler ADC and NetScaler Gateway", 1), WL, "2026-11-10")
        self.assertEqual(s, 40 + 15 + 25)
        self.assertEqual(score.priority(s), "P1")
        self.assertEqual(hits[0]["id"], "citrix-netscaler")
        self.assertEqual(len(reasons), 3)

    def test_vendor_only_match(self):
        s, _, hits = score.score_record(rec("Microsoft", "Internet Explorer"), WL, "2026-11-10")
        self.assertEqual(hits[0]["level"], "vendor")
        self.assertEqual(s, WL["vendor_only_points"])

    def test_product_hit_beats_vendor_hit(self):
        # Microsoft has several entries; Exchange must win over vendor-only hits.
        hits = score.match_watchlist("Microsoft", "Exchange Server", WL)
        self.assertEqual(hits[0]["id"], "ms-exchange")

    def test_whole_word_matching(self):
        self.assertEqual(score.match_watchlist("Cisco", "Enterprise Chat", WL)[0]["level"], "vendor")
        self.assertEqual(score.match_watchlist("Sapido", "Router", WL), [])

    def test_recency(self):
        s, _, _ = score.score_record(rec("Nobody", "Nothing", added="2026-11-01"), WL, "2026-11-10")
        self.assertEqual(s, score.RECENT_30_POINTS)

    def test_unlisted_scores_zero(self):
        s, reasons, hits = score.score_record(rec("Nobody", "Nothing"), WL, "2026-11-10")
        self.assertEqual((s, reasons, hits), (0, [], []))

    def test_every_entry_declares_sourcing(self):
        for e in WL["entries"]:
            self.assertEqual(e.get("prevalence"), "analyst-judgment", e["id"])
            self.assertIn("evidence", e, e["id"])
            for ref in e["evidence"]:
                self.assertRegex(ref, r"^kev:CVE-\d{4}-\d{4,}$", e["id"])

    def test_log4j2_and_cleo_match_at_product_level(self):
        self.assertEqual(score.match_watchlist("Apache", "Log4j2", WL)[0]["level"], "product")
        self.assertEqual(score.match_watchlist("Cleo", "Multiple Products", WL)[0]["level"], "product")

    @unittest.skipUnless(collect.LATEST.exists(), "no cached full KEV feed")
    def test_evidence_verifies_against_full_feed(self):
        feed, _ = collect.load_cached()
        with tempfile.TemporaryDirectory() as d:
            conn = store.connect(Path(d) / "t.db")
            store.load(conn, feed, "test")
            check = score.verify_evidence(conn, WL)
            conn.close()
        self.assertEqual(check["mismatch"], [])
        self.assertEqual(check["not_loaded"], [])

    def test_capped_at_100(self):
        s, _, _ = score.score_record(rec("Citrix", "NetScaler", 1, "2026-11-09"), WL, "2026-11-10")
        self.assertLessEqual(s, 100)


if __name__ == "__main__":
    unittest.main()
