"""
Tests for the DevSecOps layer: Terraform IAM extraction, the CI guardrails gate
(exit codes + SARIF), the deterministic remediation report, and config-driven custom rules.

Run:  python3 tests/test_devsecops.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("AUTH_ENABLED", "false")

import terraform_extract
import remediation
from providers import analyze_policy
from iam_engine import analyze_iam_policy

AWS_BAD = {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}
AWS_GOOD = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::app/*"}]}


def make_plan(resources):
    return {"planned_values": {"root_module": {"resources": resources}}}


class TestTerraformExtract(unittest.TestCase):
    def test_extracts_aws_policy_and_trust(self):
        plan = make_plan([
            {"address": "aws_iam_policy.p", "type": "aws_iam_policy", "name": "p",
             "values": {"policy": json.dumps(AWS_BAD)}},
            {"address": "aws_iam_role.r", "type": "aws_iam_role", "name": "r",
             "values": {"assume_role_policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]})}},
        ])
        got = terraform_extract.extract_policies(plan)
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0]["provider"], "aws")
        self.assertEqual(got[0]["policy"], AWS_BAD)

    def test_extracts_azure_role_definition(self):
        plan = make_plan([{"address": "azurerm_role_definition.o", "type": "azurerm_role_definition", "name": "o",
                           "values": {"name": "o", "permissions": [{"actions": ["Microsoft.Authorization/roleAssignments/write"], "not_actions": []}],
                                      "assignable_scopes": ["/"]}}])
        got = terraform_extract.extract_policies(plan)
        self.assertEqual(got[0]["provider"], "azure")
        scan, prov = analyze_policy(got[0]["policy"])
        self.assertEqual(prov, "azure")
        self.assertIn("AZ.ESC_ROLE_ASSIGNMENT_WRITE", {f.rule_id for f in scan.deduped()})

    def test_extracts_gcp_custom_role_and_binding(self):
        plan = make_plan([
            {"address": "google_project_iam_custom_role.c", "type": "google_project_iam_custom_role", "name": "c",
             "values": {"permissions": ["iam.serviceAccounts.actAs", "storage.objects.get"]}},
            {"address": "google_project_iam_binding.b", "type": "google_project_iam_binding", "name": "b",
             "values": {"role": "roles/owner", "members": ["allUsers"]}},
        ])
        got = terraform_extract.extract_policies(plan)
        self.assertEqual({g["provider"] for g in got}, {"gcp"})

    def test_reads_resource_changes_fallback(self):
        plan = {"resource_changes": [{"address": "aws_iam_policy.x", "type": "aws_iam_policy", "name": "x",
                                      "change": {"after": {"policy": json.dumps(AWS_BAD)}}}]}
        self.assertEqual(len(terraform_extract.extract_policies(plan)), 1)


class TestGuardrailsGate(unittest.TestCase):
    def _run(self, args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "guardrails.py"), *args],
                              capture_output=True, text=True, cwd=ROOT)

    def test_vulnerable_policy_fails_build(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(AWS_BAD, f); path = f.name
        r = self._run([path, "--fail-on", "HIGH"])
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("FAIL", r.stdout)

    def test_clean_policy_passes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(AWS_GOOD, f); path = f.name
        r = self._run([path, "--fail-on", "HIGH"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS", r.stdout)

    def test_threshold_respected(self):
        # A MEDIUM-only policy passes when fail-on=HIGH.
        med = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::1:role/x"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(med, f); path = f.name
        self.assertEqual(self._run([path, "--fail-on", "HIGH"]).returncode, 0)
        self.assertEqual(self._run([path, "--fail-on", "MEDIUM"]).returncode, 1)

    def test_sarif_output_is_valid(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(AWS_BAD, f); path = f.name
        r = self._run([path, "--format", "sarif", "--fail-on", "INFO"])
        doc = json.loads(r.stdout)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_markdown_output_and_comment_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(AWS_BAD, f); path = f.name
        comment_file = path + ".md"
        r = self._run([path, "--format", "markdown", "--comment-file", comment_file, "--fail-on", "HIGH"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("IAM Sentinel Guardrails Audit Report", r.stdout)
        self.assertIn("| Status | Provider | Policy / Resource |", r.stdout)
        self.assertTrue(os.path.exists(comment_file))
        with open(comment_file, "r") as cf:
            self.assertIn("IAM Sentinel Guardrails Audit Report", cf.read())
        os.remove(comment_file)



class TestRemediation(unittest.TestCase):
    def test_report_lists_fixes_no_llm(self):
        scan, prov = analyze_policy(AWS_BAD)
        rep = remediation.build_report(scan, prov)
        self.assertIn("Remediation Report", rep)
        self.assertIn("IAM.ESC_PASSROLE_EC2", rep)
        self.assertIn("Least-privilege", rep)

    def test_clean_report_says_pass(self):
        scan, prov = analyze_policy(AWS_GOOD)
        self.assertIn("PASS", remediation.build_report(scan, prov))


class TestCustomRules(unittest.TestCase):
    def test_custom_rule_from_file(self):
        # Point CUSTOM_RULES_FILE at a temp file, reload the engine, verify it fires.
        rule = {"escalation_primitives": [{"id": "IAM.ESC_TEST_CUSTOM",
                                           "actions": ["ssm:SendCommand", "ec2:DescribeInstances"],
                                           "name": "custom test"}]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(rule, f); path = f.name
        os.environ["CUSTOM_RULES_FILE"] = path
        import importlib, iam_engine
        importlib.reload(iam_engine)
        pol = {"Statement": [{"Effect": "Allow",
                              "Action": ["ssm:SendCommand", "ec2:DescribeInstances"],
                              "Resource": "arn:aws:ec2:::instance/*"}]}
        ids = {f.rule_id for f in iam_engine.analyze_iam_policy(pol).deduped()}
        self.assertIn("IAM.ESC_TEST_CUSTOM", ids)
        os.environ.pop("CUSTOM_RULES_FILE", None)
        importlib.reload(iam_engine)  # restore default rules for other tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
