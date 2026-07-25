"""
Tests for the persistence & audit store. Pure stdlib (sqlite3 + unittest).

Run:  python3 test_store.py
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("AUTH_ENABLED", "false")

from findings import Finding, ScanResult, Severity
from store import FindingsStore


def make_scan(target, rule_ids):
    scan = ScanResult(domain="iam", target=target)
    scan.engine_version = "3.5.0"
    scan.ruleset_version = "iam-2026.07"
    scan.artifact_sha256 = "deadbeef" * 8
    for rid in rule_ids:
        scan.add(Finding(rule_id=rid, title=rid, severity=Severity.HIGH,
                         domain="iam", description="x", evidence=rid, location=rid))
    return scan.to_dict()


class TestFindingsStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = FindingsStore(db_path=os.path.join(self.tmp, "test.db"))

    def test_record_and_retrieve(self):
        sid = self.store.record_scan(make_scan("policyA", ["IAM.A", "IAM.B"]), actor="jane")
        got = self.store.get_scan(sid)
        self.assertEqual(got["actor"], "jane")
        self.assertEqual(got["finding_count"], 2)
        self.assertEqual(len(got["findings"]), 2)
        self.assertEqual(got["ruleset_version"], "iam-2026.07")

    def test_audit_log_written_on_scan(self):
        self.store.record_scan(make_scan("policyA", ["IAM.A"]), actor="ci-bot", request_id="req-1")
        audit = self.store.recent_audit()
        self.assertTrue(any(a["action"] == "record_scan" and a["actor"] == "ci-bot" for a in audit))

    def test_diff_shows_fixed_new_persistent(self):
        # First scan: A + B present.
        self.store.record_scan(make_scan("policyA", ["IAM.A", "IAM.B"]), actor="jane")
        # Second scan after remediation: A fixed, B remains, C newly introduced.
        self.store.record_scan(make_scan("policyA", ["IAM.B", "IAM.C"]), actor="jane")
        diff = self.store.diff_latest("iam", "policyA")
        self.assertIsNotNone(diff)
        fixed = {f["rule_id"] for f in diff["fixed"]}
        new = {f["rule_id"] for f in diff["new"]}
        persistent = {f["rule_id"] for f in diff["persistent"]}
        self.assertEqual(fixed, {"IAM.A"})
        self.assertEqual(new, {"IAM.C"})
        self.assertEqual(persistent, {"IAM.B"})

    def test_diff_none_with_single_scan(self):
        self.store.record_scan(make_scan("solo", ["IAM.A"]), actor="jane")
        self.assertIsNone(self.store.diff_latest("iam", "solo"))

    def test_list_scans_filters(self):
        self.store.record_scan(make_scan("p1", ["IAM.A"]), actor="jane")
        self.store.record_scan(make_scan("p2", ["IAM.B"]), actor="jane")
        self.assertEqual(len(self.store.list_scans(target="p1")), 1)
        self.assertEqual(len(self.store.list_scans()), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
