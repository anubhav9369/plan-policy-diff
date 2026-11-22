"""Tests for policy_diff.py — 9 stdlib tests, no network."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from policy_diff import PackError, classify_change, diff_packs, load_pack, render_markdown


def pack(rules, version="1.0.0"):
    return {"id": "default", "version": version, "rules": rules}


def rule(rid, matcher="require_reason", params=None, severity="medium",
         category="ethics", description="d"):
    return {"id": rid, "category": category, "matcher": matcher,
            "params": params or {}, "severity": severity,
            "description": description}


class TestDiff(unittest.TestCase):
    def test_identical_packs_no_findings(self):
        report = diff_packs(pack([rule("ETH-01")]), pack([rule("ETH-01")]))
        self.assertEqual(report["counts"], {"tightening": 0, "loosening": 0, "neutral": 0})
        self.assertEqual(report["verdict"], "no re-check needed")
        self.assertEqual(report["findings"], [])

    def test_added_rule_is_tightening(self):
        report = diff_packs(pack([]), pack([rule("SEC-04", "forbid_action",
                                                 {"actions": ["scrape"]}, "high", "security")]))
        self.assertEqual(report["counts"]["tightening"], 1)
        self.assertEqual(report["verdict"], "re-check approved plans")
        self.assertEqual(report["findings"][0]["change"], "added")

    def test_removed_rule_is_loosening(self):
        report = diff_packs(pack([rule("ETH-02")]), pack([]))
        self.assertEqual(report["counts"]["loosening"], 1)
        self.assertEqual(report["verdict"], "no re-check needed")

    def test_spend_limit_lowered_is_tightening(self):
        old = pack([rule("ORG-01", "max_total_cost", {"limit_usd": 5.0}, "medium", "org")])
        new = pack([rule("ORG-01", "max_total_cost", {"limit_usd": 2.0}, "medium", "org")])
        report = diff_packs(old, new)
        self.assertEqual(report["counts"]["tightening"], 1)
        self.assertIn("'limit_usd': 5.0", report["findings"][0]["detail"])
        self.assertIn("'limit_usd': 2.0", report["findings"][0]["detail"])

    def test_spend_limit_raised_is_loosening(self):
        old = pack([rule("ORG-01", "max_total_cost", {"limit_usd": 2.0}, "medium", "org")])
        new = pack([rule("ORG-01", "max_total_cost", {"limit_usd": 10.0}, "medium", "org")])
        report = diff_packs(old, new)
        self.assertEqual(report["counts"]["loosening"], 1)
        self.assertEqual(report["counts"]["tightening"], 0)

    def test_severity_raised_is_tightening(self):
        old = pack([rule("SEC-01", "require_gate", {"actions": ["send"]}, "medium", "security")])
        new = pack([rule("SEC-01", "require_gate", {"actions": ["send"]}, "high", "security")])
        report = diff_packs(old, new)
        self.assertEqual(report["counts"]["tightening"], 1)
        self.assertIn("medium -> high", report["findings"][0]["detail"])

    def test_description_only_change_is_neutral(self):
        old = pack([rule("ETH-01", description="old wording")])
        new = pack([rule("ETH-01", description="new wording")])
        kind, detail = classify_change(old["rules"][0], new["rules"][0])
        self.assertEqual(kind, "neutral")
        self.assertIn("reworded", detail)

    def test_duplicate_rule_id_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(pack([rule("ETH-01"), rule("ETH-01")]), fh)
            path = fh.name
        try:
            with self.assertRaises(PackError):
                load_pack(path)
        finally:
            os.unlink(path)

    def test_cli_example_verdict_and_json(self):
        old = os.path.join(ROOT, "examples", "pack-v1.json")
        new = os.path.join(ROOT, "examples", "pack-v2.json")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "policy_diff.py"), old, new, "--json"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 1)  # tightening present
        report = json.loads(proc.stdout)
        self.assertEqual(report["counts"], {"tightening": 3, "loosening": 1, "neutral": 0})
        self.assertEqual(report["verdict"], "re-check approved plans")
        md = render_markdown(report)
        self.assertIn("SEC-04", md)
        self.assertIn("re-check", md.lower())


if __name__ == "__main__":
    unittest.main()
