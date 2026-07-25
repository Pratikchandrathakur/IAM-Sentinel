"""
Fixture-based tests for the deterministic IAM engine.

This is the seed of the eval harness (vision item #7): every rule is pinned to a
known-good / known-bad fixture so we can measure precision and catch regressions.
Pure stdlib + unittest — runs without torch/llama-index.

Run:  python3 test_iam_engine.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from findings import Severity
from iam_engine import analyze_iam_policy


def rule_ids(result):
    return {f.rule_id for f in result.deduped()}


class TestIamEngine(unittest.TestCase):

    def test_clean_least_privilege_policy_is_quiet(self):
        """A properly scoped policy should raise ZERO findings (precision guard)."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "ReadOneBucket",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-app-bucket/reports/*",
            }],
        }
        result = analyze_iam_policy(policy)
        self.assertEqual(result.findings, [], f"clean policy raised: {rule_ids(result)}")
        self.assertEqual(result.highest_severity, Severity.INFO)

    def test_full_wildcard_is_critical_and_deduped(self):
        """Action:* Resource:* => one dominating CRITICAL, no escalation-primitive flood."""
        policy = {"Statement": [{"Sid": "God", "Effect": "Allow", "Action": "*", "Resource": "*"}]}
        result = analyze_iam_policy(policy)
        ids = rule_ids(result)
        self.assertIn("IAM.WILDCARD_ACTION_ALL", ids)
        self.assertNotIn("IAM.ESC_ATTACH_USER_POLICY", ids,
                         "granular escalation rules should be suppressed under global '*'")
        self.assertEqual(result.highest_severity, Severity.CRITICAL)

    def test_scoped_looking_but_escalatable(self):
        """The important case: no wildcard action, yet a real escalation path exists."""
        policy = {
            "Statement": [{
                "Sid": "LooksFine",
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey"],
                "Resource": "arn:aws:iam::123456789012:user/*",
            }],
        }
        result = analyze_iam_policy(policy)
        self.assertIn("IAM.ESC_CREATE_ACCESS_KEY", rule_ids(result))

    def test_passrole_plus_runinstances_chain(self):
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
            ],
        }
        ids = rule_ids(analyze_iam_policy(policy))
        self.assertIn("IAM.ESC_PASSROLE_EC2", ids)
        self.assertIn("IAM.PASSROLE_WILDCARD", ids)

    def test_service_wildcard_iam_is_critical(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        result = analyze_iam_policy(policy)
        self.assertIn("IAM.WILDCARD_ACTION_SERVICE", rule_ids(result))
        self.assertEqual(result.highest_severity, Severity.CRITICAL)

    def test_notaction_allow_trap(self):
        policy = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
        self.assertIn("IAM.NOTACTION_ALLOW", rule_ids(analyze_iam_policy(policy)))

    def test_wildcard_principal_no_condition_is_critical(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Principal": "*",
            "Action": "sts:AssumeRole", "Resource": "*",
        }]}
        result = analyze_iam_policy(policy)
        self.assertIn("IAM.WILDCARD_PRINCIPAL", rule_ids(result))
        crit = [f for f in result.findings if f.rule_id == "IAM.WILDCARD_PRINCIPAL"][0]
        self.assertEqual(crit.severity, Severity.CRITICAL)

    def test_assumerole_without_condition(self):
        policy = {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/app",
        }]}
        self.assertIn("IAM.ASSUMEROLE_NO_CONDITION", rule_ids(analyze_iam_policy(policy)))

    def test_assumerole_with_condition_is_quiet(self):
        """MFA-conditioned AssumeRole should NOT flag the no-condition rule."""
        policy = {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/app",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }]}
        self.assertNotIn("IAM.ASSUMEROLE_NO_CONDITION", rule_ids(analyze_iam_policy(policy)))

    def test_non_policy_input_reports_parse_error(self):
        result = analyze_iam_policy({"foo": "bar"})
        self.assertTrue(result.parse_errors)
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
