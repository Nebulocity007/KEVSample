"""Collect-stage tests. No network: exercises validation, caching and fallback."""

import json
import tempfile
import unittest
from pathlib import Path

from fin_ti import collect

FEED = {"catalogVersion": "t", "vulnerabilities": [{"cveID": "CVE-0000-0001"}]}


class CollectTests(unittest.TestCase):
    def test_validate_rejects_non_kev(self):
        with self.assertRaises(ValueError):
            collect.validate({"html": "captive portal"})

    def test_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            raw = Path(d)
            collect.save_cache(FEED, raw)
            feed, label = collect.load_cached(raw, sample=raw / "missing.json")
            self.assertEqual(feed, FEED)
            self.assertIn("cache", label)

    def test_falls_back_to_sample(self):
        with tempfile.TemporaryDirectory() as d:
            sample = Path(d) / "sample.json"
            sample.write_text(json.dumps(FEED), encoding="utf-8")
            _, label = collect.load_cached(Path(d) / "empty", sample=sample)
            self.assertEqual(label, "bundled sample")

    def test_bundled_sample_is_valid(self):
        feed = json.loads(collect.SAMPLE.read_text(encoding="utf-8"))
        collect.validate(feed)
        self.assertGreater(len(feed["vulnerabilities"]), 10)


if __name__ == "__main__":
    unittest.main()
