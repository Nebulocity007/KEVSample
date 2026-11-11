"""Tag-stage tests: ATT&CK rules, ICD 203 likelihood bands, confidence logic."""

import json
import unittest

from fin_ti import score, tag

WL = score.load_watchlist()
RULES = tag.load_rules()


def rec(vendor, product, name="", desc="", cwes=(), ransomware=0):
    return {"vendor": vendor, "product": product, "name": name, "description": desc,
            "cwes": json.dumps(list(cwes)), "ransomware": ransomware}


def ids(r):
    hits = score.match_watchlist(r["vendor"], r["product"], WL)
    return {t["id"] for t in tag.tag_record(r, hits, RULES)}, hits


class TagTests(unittest.TestCase):
    def test_panos_command_injection(self):
        r = rec("Palo Alto Networks", "PAN-OS", "PAN-OS Command Injection",
                "GlobalProtect feature allows unauthenticated attacker ...", ["CWE-77"], 1)
        got, _ = ids(r)
        self.assertTrue({"T1190", "T1133", "T1059", "T1486"} <= got)

    def test_windows_lpe(self):
        got, _ = ids(rec("Microsoft", "Windows", "Windows CLFS Privilege Escalation",
                         "allows for privilege escalation"))
        self.assertIn("T1068", got)
        self.assertNotIn("T1190", got)  # not internet-facing

    def test_rdp_proxy_mention_is_not_lateral_movement(self):
        got, _ = ids(rec("Citrix", "NetScaler", desc="configured as a Gateway (SSL VPN, RDP Proxy)"))
        self.assertNotIn("T1210", got)
        got, _ = ids(rec("Microsoft", "Remote Desktop Services", desc="connect using RDP"))
        self.assertIn("T1210", got)

    def test_windows_lpe_is_not_client_execution(self):
        got, _ = ids(rec("Microsoft", "Windows", desc="allows for privilege escalation"))
        self.assertNotIn("T1203", got)

    def test_browser_drive_by(self):
        got, _ = ids(rec("Google", "Chromium V8", "Use-After-Free", "via a crafted HTML page"))
        self.assertTrue({"T1189", "T1203"} <= got)

    def test_evidence_basis_preferred(self):
        r = rec("Palo Alto Networks", "PAN-OS", desc="unauthenticated attacker")
        hits = score.match_watchlist(r["vendor"], r["product"], WL)
        t1190 = next(t for t in tag.tag_record(r, hits, RULES) if t["id"] == "T1190")
        self.assertEqual(t1190["basis"], "evidence")

    def test_likelihood_bands_and_cap(self):
        self.assertEqual(tag.likelihood(100)[0], "very likely")  # never "almost certain"
        self.assertEqual(tag.likelihood(70)[0], "likely")
        self.assertEqual(tag.likelihood(0)[0], "almost no chance")

    def test_confidence_levels(self):
        r = rec("Citrix", "NetScaler ADC", cwes=["CWE-200"], ransomware=1)
        got, hits = ids(r)
        tags = tag.tag_record(r, hits, RULES)
        self.assertEqual(tag.confidence(r, hits, tags)[0], "high")
        r2 = rec("Nobody", "Nothing")
        self.assertEqual(tag.confidence(r2, [], [])[0], "low")

    def test_statement_names_question_elements(self):
        s = tag.estimative_statement("CVE-1", "V", "P", 70, "moderate", ["x"])
        self.assertIn("likely (55-80%)", s)
        self.assertIn("moderate confidence", s)


if __name__ == "__main__":
    unittest.main()
