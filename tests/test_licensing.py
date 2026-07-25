"""
Tests for offline licensing + usage metering.

Signature tests need `cryptography` (shipped in requirements); they self-skip if absent.
Quota/expiry/plan logic is tested regardless.

Run:  python3 tests/test_licensing.py
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("AUTH_ENABLED", "false")

import licensing
import metering
from store import FindingsStore

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False


def _keypair():
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, licensing._b64url_encode(raw_pub)


def _sign(priv, payload: dict) -> str:
    pb = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = priv.sign(pb)
    return licensing._b64url_encode(pb) + "." + licensing._b64url_encode(sig)


class TestLicensing(unittest.TestCase):
    def test_community_fallback_when_no_license(self):
        os.environ.pop("LICENSE_KEY", None)
        lic = licensing.load_active_license()
        self.assertEqual(lic.plan, "community")
        self.assertFalse(lic.signed)
        self.assertEqual(lic.max_scans_per_month, 100)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_valid_signed_license_verifies(self):
        priv, pub = _keypair()
        token = _sign(priv, {"plan": "enterprise", "customer": "Acme", "seats": 25,
                             "max_scans_per_month": 0, "features": ["audit", "sso", "rbac"],
                             "expires": ""})
        lic = licensing.verify_license(token, pub)
        self.assertTrue(lic.signed)
        self.assertEqual(lic.plan, "enterprise")
        self.assertEqual(lic.seats, 25)
        self.assertTrue(lic.has_feature("sso"))

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_tampered_license_rejected(self):
        priv, pub = _keypair()
        token = _sign(priv, {"plan": "team", "customer": "Acme", "seats": 10})
        payload_b64, sig = token.split(".")
        # Flip the payload to claim enterprise while keeping the old signature.
        forged_payload = licensing._b64url_encode(
            json.dumps({"plan": "enterprise", "customer": "Acme", "seats": 999},
                       separators=(",", ":"), sort_keys=True).encode())
        forged = forged_payload + "." + sig
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(forged, pub)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_expired_license_rejected(self):
        priv, pub = _keypair()
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        token = _sign(priv, {"plan": "team", "customer": "Acme", "expires": yesterday})
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(token, pub)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_wrong_key_rejected(self):
        priv, _ = _keypair()
        _, other_pub = _keypair()
        token = _sign(priv, {"plan": "team", "customer": "Acme"})
        with self.assertRaises(licensing.LicenseError):
            licensing.verify_license(token, other_pub)


class TestMetering(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = FindingsStore(db_path=os.path.join(self.tmp, "m.db"))

    def _scan_dict(self, actor):
        return {"domain": "iam", "target": "t", "artifact_sha256": "x",
                "engine_version": "1.0.0", "ruleset_version": "r", "highest_severity": "LOW",
                "finding_count": 0, "severity_counts": {}, "findings": []}

    def test_scan_quota_blocks_new_scan(self):
        lic = licensing.License(plan="community", seats=0, max_scans_per_month=2)
        self.store.record_scan(self._scan_dict("a"), actor="a")
        self.store.record_scan(self._scan_dict("a"), actor="a")
        with self.assertRaises(metering.QuotaExceeded) as ctx:
            metering.enforce_quota(self.store, lic, "a")
        self.assertEqual(ctx.exception.kind, "scans")

    def test_unlimited_plan_never_blocks(self):
        lic = licensing.License(plan="enterprise", seats=0, max_scans_per_month=0)
        for _ in range(50):
            self.store.record_scan(self._scan_dict("a"), actor="a")
        metering.enforce_quota(self.store, lic, "a")  # no raise

    def test_seat_limit_blocks_new_actor_only(self):
        lic = licensing.License(plan="team", seats=1, max_scans_per_month=0)
        self.store.record_scan(self._scan_dict("jane"), actor="jane")
        metering.enforce_quota(self.store, lic, "jane")          # existing seat -> ok
        with self.assertRaises(metering.QuotaExceeded) as ctx:
            metering.enforce_quota(self.store, lic, "bob")       # new actor over seat cap
        self.assertEqual(ctx.exception.kind, "seats")

    def test_usage_summary_shape(self):
        lic = licensing.License(plan="team", seats=10, max_scans_per_month=5000)
        self.store.record_scan(self._scan_dict("jane"), actor="jane")
        summary = metering.usage_summary(self.store, lic)
        self.assertEqual(summary["scans_used"], 1)
        self.assertEqual(summary["seats_used"], 1)
        self.assertEqual(summary["scans_remaining"], 4999)


if __name__ == "__main__":
    unittest.main(verbosity=2)
