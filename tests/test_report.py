"""End-to-end test: bundled sample -> temp DB -> both Markdown reports."""

import json
import tempfile
import unittest
from pathlib import Path

from fin_ti import collect, report, score, store, tag


class ReportTests(unittest.TestCase):
    def test_pipeline_on_sample(self):
        feed = json.loads(collect.SAMPLE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            conn = store.connect(Path(d) / "t.db")
            store.load(conn, feed, "sample")
            ref = store.as_of(conn)
            score.score_all(conn, score.load_watchlist(), ref)
            tag.tag_all(conn, tag.load_rules())
            tactical, brief = report.write_reports(conn, ref, out_dir=Path(d))
            conn.close()
            t, b = tactical.read_text(encoding="utf-8"), brief.read_text(encoding="utf-8")

        self.assertIn("CVE-2023-4966", t)                      # Citrix Bleed is P1/P2
        self.assertIn("TLP:CLEAR", b)
        for section in ("Bottom Line Up Front", "Key Judgments", "Priority Vulnerabilities",
                        "Recommended Actions", "Method"):
            self.assertIn(section, b)
        self.assertNotIn("Top 5 Actions", b)                   # was confused with actions list
        self.assertNotIn("almost certain", b)                  # ICD 203 cap holds
        self.assertIn("this category of vulnerability", b)     # brief-level question
        self.assertIn("exploitation, not targeting", b)
        self.assertIn("all-time", b)
        self.assertIn("ties broken by most recent KEV addition", b)
        self.assertIn("not a trend", b)
        self.assertIn("analyst-curated", b)                    # watchlist provenance stated
        for banned in ("typically via phishing", "dominant initial-access route",
                       "frequently reported", "our financial-sector watchlist"):
            self.assertNotIn(banned, b)
        ransom_kj = next(l for l in b.splitlines() if l.startswith("- **Ransomware"))
        self.assertIn("moderate confidence", ransom_kj)        # capped: single source
        self.assertLess(len(b.splitlines()), 60)               # stays ~one page

    def test_group_by_product_keeps_rank_order(self):
        items = [{"vendor": "A", "product": "x", "id": 1}, {"vendor": "B", "product": "y", "id": 2},
                 {"vendor": "A", "product": "x", "id": 3}]
        groups = report.group_by_product(items)
        self.assertEqual([g for g, _ in groups], ["A x", "B y"])
        self.assertEqual([r["id"] for r in groups[0][1]], [1, 3])

    def test_markdown_cell_escaping(self):
        self.assertEqual(report.md("a|b\nc"), "a\\|b c")


if __name__ == "__main__":
    unittest.main()
