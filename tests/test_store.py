"""Store-stage tests against an in-memory-style temp SQLite DB."""

import json
import tempfile
import unittest
from pathlib import Path

from fin_ti import store

REC = {
    "cveID": " cve-2023-4966 ", "vendorProject": "Citrix",
    "product": "NetScaler ADC and NetScaler Gateway", "vulnerabilityName": "Citrix Bleed",
    "dateAdded": "2023-10-18", "dueDate": "2023-11-08",
    "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-119", "CWE-119"],
}
FEED = {"catalogVersion": "v1", "dateReleased": "2026-11-10T19:03:29Z", "vulnerabilities": [REC]}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = store.connect(Path(self.tmp.name) / "t.db")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_normalize(self):
        n = store.normalize(REC)
        self.assertEqual(n["cve_id"], "CVE-2023-4966")
        self.assertEqual(n["ransomware"], 1)
        self.assertEqual(json.loads(n["cwes"]), ["CWE-119"])  # deduplicated

    def test_upsert_is_idempotent_and_keeps_first_seen(self):
        self.assertEqual(store.load(self.conn, FEED, "test")["new"], 1)
        first = self.conn.execute("SELECT first_seen FROM vulns").fetchone()[0]
        stats = store.load(self.conn, FEED, "test")
        self.assertEqual((stats["new"], stats["updated"]), (0, 1))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT first_seen FROM vulns").fetchone()[0], first)

    def test_as_of_uses_feed_date(self):
        store.load(self.conn, FEED, "test")
        self.assertEqual(store.as_of(self.conn), "2026-11-10")


if __name__ == "__main__":
    unittest.main()
