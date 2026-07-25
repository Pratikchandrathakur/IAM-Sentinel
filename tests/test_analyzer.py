"""
Tests for the grounded analyzer: provenance stamping + LLM-outage resilience.
The deterministic findings must always survive a model failure.

Run:  python3 tests/test_analyzer.py
"""

import os
import sys
import types
import importlib
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("AUTH_ENABLED", "false")


class TestAnalyzer(unittest.TestCase):
    def _analyzer_with_llm(self, raises=False):
        """Return a fresh analyzer module with a stubbed llm_client."""
        stub = types.ModuleType("llm_client")

        class LLMUnavailable(RuntimeError):
            pass

        class LLMClient:
            def __init__(self, backend="ollama"):
                pass

            def query(self, **kw):
                if raises:
                    raise LLMUnavailable("backend down")
                return "NARRATIVE OK"

        stub.LLMClient = LLMClient
        stub.LLMUnavailable = LLMUnavailable
        sys.modules["llm_client"] = stub

        os.environ["LLM_NARRATIVE_ENABLED"] = "true"
        import config
        importlib.reload(config)
        import analyzer
        importlib.reload(analyzer)
        return analyzer, config

    def test_findings_survive_llm_outage(self):
        analyzer, config = self._analyzer_with_llm(raises=True)
        policy = {"Statement": [{"Effect": "Allow",
                                 "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}
        res = analyzer.analyze(policy, structured=True)
        self.assertFalse(res["llm_narrative_ok"])
        self.assertGreaterEqual(res["scan"]["finding_count"], 2)
        # On LLM outage the report falls back to the deterministic remediation (never empty).
        self.assertIn("IAM.ESC_PASSROLE_EC2", res["report"])
        self.assertIn("Remediation Report", res["report"])

    def test_provenance_stamped(self):
        analyzer, config = self._analyzer_with_llm(raises=False)
        res = analyzer.analyze({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                               structured=True)
        scan = res["scan"]
        self.assertEqual(scan["engine_version"], config.ENGINE_VERSION)
        self.assertEqual(scan["ruleset_version"], config.RULESET_VERSION)
        self.assertTrue(scan["artifact_sha256"])
        self.assertTrue(scan["scanned_at"])
        self.assertTrue(res["llm_narrative_ok"])

    def test_canonical_digest_is_key_order_independent(self):
        analyzer, _ = self._analyzer_with_llm(raises=False)
        a = analyzer.analyze({"Effect": "x", "Statement": []}, structured=True)["scan"]["artifact_sha256"]
        b = analyzer.analyze({"Statement": [], "Effect": "x"}, structured=True)["scan"]["artifact_sha256"]
        self.assertEqual(a, b)

    def test_narrative_disabled_mode(self):
        analyzer, _ = self._analyzer_with_llm(raises=False)
        os.environ["LLM_NARRATIVE_ENABLED"] = "false"
        import config
        importlib.reload(config)
        importlib.reload(analyzer)
        res = analyzer.analyze({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                               structured=True)
        # With no model, the report IS the deterministic remediation — fully useful offline.
        self.assertIn("Remediation Report", res["report"])
        self.assertTrue(res["llm_narrative_ok"])
        self.assertGreaterEqual(res["scan"]["finding_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
