"""
Tests for the Azure + GCP deterministic engines and the provider dispatcher.

Run:  python3 tests/test_multicloud.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("AUTH_ENABLED", "false")

from findings import Severity
from iam_engine_azure import analyze_azure_role
from iam_engine_gcp import analyze_gcp_policy
from providers import analyze_policy, detect_provider


def rids(scan):
    return {f.rule_id for f in scan.deduped()}


class TestAzure(unittest.TestCase):
    def test_role_assignment_write_is_escalation(self):
        role = {"properties": {"roleName": "sneaky", "permissions": [
            {"actions": ["Microsoft.Authorization/roleAssignments/write"], "notActions": []}],
            "assignableScopes": ["/subscriptions/abc"]}}
        scan = analyze_azure_role(role)
        self.assertIn("AZ.ESC_ROLE_ASSIGNMENT_WRITE", rids(scan))
        self.assertEqual(scan.highest_severity, Severity.CRITICAL)

    def test_wildcard_actions_owner_equivalent(self):
        role = {"properties": {"roleName": "godmode", "permissions": [{"actions": ["*"]}],
                               "assignableScopes": ["/"]}}
        ids = rids(analyze_azure_role(role))
        self.assertIn("AZ.WILDCARD_ACTION_ALL", ids)
        self.assertIn("AZ.SCOPE_ROOT", ids)

    def test_clean_azure_role_quiet(self):
        role = {"properties": {"roleName": "reader", "permissions": [
            {"actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"]}],
            "assignableScopes": ["/subscriptions/abc/resourceGroups/rg1"]}}
        scan = analyze_azure_role(role)
        self.assertEqual(scan.findings, [], f"clean role raised {rids(scan)}")


class TestGCP(unittest.TestCase):
    def test_owner_primitive_and_public_member(self):
        policy = {"bindings": [
            {"role": "roles/owner", "members": ["user:x@y.com"]},
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
        ]}
        scan = analyze_gcp_policy(policy)
        ids = rids(scan)
        self.assertIn("GCP.PRIMITIVE_ROLE", ids)
        self.assertIn("GCP.PUBLIC_MEMBER", ids)
        self.assertEqual(scan.highest_severity, Severity.CRITICAL)

    def test_token_creator_escalation_role(self):
        policy = {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator",
                                "members": ["user:x@y.com"]}]}
        self.assertIn("GCP.ESC_ROLE", rids(analyze_gcp_policy(policy)))

    def test_custom_role_actas_permission(self):
        policy = {"includedPermissions": ["iam.serviceAccounts.actAs", "storage.objects.get"]}
        self.assertIn("GCP.ESC_PERMISSION", rids(analyze_gcp_policy(policy)))

    def test_clean_gcp_policy_quiet(self):
        policy = {"bindings": [{"role": "roles/storage.objectViewer",
                                "members": ["serviceAccount:app@proj.iam.gserviceaccount.com"]}]}
        scan = analyze_gcp_policy(policy)
        self.assertEqual(scan.findings, [], f"clean policy raised {rids(scan)}")


class TestDispatcher(unittest.TestCase):
    def test_detects_aws(self):
        self.assertEqual(detect_provider({"Statement": [{"Effect": "Allow", "Action": "*"}]}), "aws")

    def test_detects_azure(self):
        self.assertEqual(detect_provider(
            {"properties": {"permissions": [{"actions": ["Microsoft.Compute/*"]}]}}), "azure")

    def test_detects_gcp(self):
        self.assertEqual(detect_provider({"bindings": [{"role": "roles/owner", "members": []}]}), "gcp")

    def test_dispatch_routes_and_stamps_provider(self):
        scan, prov = analyze_policy({"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]})
        self.assertEqual(prov, "gcp")
        self.assertEqual(scan.stats["provider"], "gcp")
        self.assertGreaterEqual(scan.finding_count, 1)

    def test_explicit_provider_override(self):
        # Force AWS engine on a doc that has a Statement — normal AWS path.
        scan, prov = analyze_policy({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]},
                                    provider="aws")
        self.assertEqual(prov, "aws")
        self.assertGreaterEqual(scan.finding_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
