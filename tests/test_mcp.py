"""
Tests for the MCP stdio server. Exercises the JSON-RPC dispatch as a pure function so the
whole protocol is verified without spawning a process or needing an LLM.

Run from the product root:  python3 -m tests.test_mcp   (or: python3 tests/test_mcp.py)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("AUTH_ENABLED", "false")
os.environ.setdefault("LLM_NARRATIVE_ENABLED", "false")  # deterministic-only for tests

import mcp_stdio


class TestMCP(unittest.TestCase):
    def test_initialize_handshake(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual(resp["id"], 1)
        self.assertIn("serverInfo", resp["result"])
        self.assertEqual(resp["result"]["serverInfo"]["name"], "iam-sentinel")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_initialized_notification_has_no_response(self):
        self.assertIsNone(mcp_stdio.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_tools_list(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"audit_iam_policy", "list_iam_rules"})
        # inputSchema must be present + declare required fields
        audit = next(t for t in resp["result"]["tools"] if t["name"] == "audit_iam_policy")
        self.assertEqual(audit["inputSchema"]["required"], ["policy_json"])

    def test_tools_call_audit_finds_escalation(self):
        policy = '{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]}'
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "audit_iam_policy",
                                              "arguments": {"policy_json": policy}}})
        text = resp["result"]["content"][0]["text"]
        self.assertFalse(resp["result"].get("isError"))
        self.assertIn("IAM.ESC_PASSROLE_EC2", text)
        self.assertIn("CRITICAL", text)

    def test_tools_call_invalid_json_is_in_band_error(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                   "params": {"name": "audit_iam_policy",
                                              "arguments": {"policy_json": "{not json"}}})
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("Invalid", resp["result"]["content"][0]["text"])

    def test_unknown_tool(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                   "params": {"name": "nope", "arguments": {}}})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32602)

    def test_unknown_method(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 6, "method": "does/not/exist"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_list_rules_tool(self):
        resp = mcp_stdio.dispatch({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                   "params": {"name": "list_iam_rules", "arguments": {}}})
        self.assertIn("IAM.ESC_", resp["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
