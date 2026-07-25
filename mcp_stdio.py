"""
IAM Sentinel — Model Context Protocol (MCP) server over stdio.

This is a REAL MCP server: newline-delimited JSON-RPC 2.0 on stdin/stdout, implementing
`initialize`, `tools/list`, and `tools/call`. It lets AI coding assistants (Claude Code,
Cursor, etc.) call the deterministic IAM auditor **locally** — so a developer writing an
IAM policy / Terraform gets privilege-escalation feedback inline, before commit, with no
data leaving the machine.

Pure stdlib. `dispatch()` is a pure function (message dict -> response dict or None for
notifications) so the whole protocol is unit-testable without spawning a process.

Register in Claude Code / Cursor (example mcp config):
    {
      "mcpServers": {
        "iam-sentinel": { "command": "python3", "args": ["/path/to/mcp_stdio.py"] }
      }
    }
"""

import json
import sys
import logging

import config
from analyzer import analyze
from iam_engine import ESCALATION_PRIMITIVES

log = logging.getLogger("iam-sentinel.mcp")

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "audit_iam_policy",
        "description": (
            "Audit an AWS, Azure, or GCP IAM/RBAC policy for privilege-escalation paths, "
            "wildcards, PassRole/roleAssignment abuse, public/unconditioned grants, and data "
            "exfiltration using a deterministic rule engine (not an LLM guess). Provider is "
            "auto-detected. Returns verified findings with severities plus least-privilege "
            "remediation. Runs fully locally."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "policy_json": {"type": "string", "description": "The IAM/RBAC policy document as a JSON string."},
                "provider": {"type": "string", "enum": ["auto", "aws", "azure", "gcp"],
                             "description": "Cloud provider (default auto-detect)."},
                "target": {"type": "string", "description": "Optional logical name for audit history."},
            },
            "required": ["policy_json"],
        },
    },
    {
        "name": "list_iam_rules",
        "description": "List the deterministic IAM privilege-escalation techniques this engine detects.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _text(s: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": s}], "isError": is_error}


def _tool_audit_iam_policy(args: dict) -> dict:
    raw = args.get("policy_json", "")
    try:
        policy = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as e:
        return _text(f"Invalid policy_json (not valid JSON): {e}", is_error=True)

    result = analyze(policy, target=args.get("target", "mcp policy"),
                     provider=args.get("provider", "auto"), structured=True)
    scan = result["scan"]
    lines = [
        f"IAM Sentinel [{result.get('provider', 'aws').upper()}] — {scan['highest_severity']} "
        f"(engine {scan['engine_version']}, ruleset {scan['ruleset_version']})",
        f"{scan['finding_count']} finding(s): {scan['severity_counts']}",
        f"artifact_sha256: {scan['artifact_sha256']}",
        "",
        "DETERMINISTIC FINDINGS:",
    ]
    if scan["findings"]:
        for f in scan["findings"]:
            lines.append(f"  - [{f['severity']}] {f['rule_id']}: {f['title']}")
            if f.get("location"):
                lines.append(f"      location: {f['location']}")
            if f.get("remediation_hint"):
                lines.append(f"      fix: {f['remediation_hint']}")
    else:
        lines.append("  (none — policy passed all deterministic checks)")
    lines += ["", "REMEDIATION NARRATIVE:", result["report"]]
    return _text("\n".join(lines))


def _tool_list_iam_rules(args: dict) -> dict:
    lines = ["IAM Sentinel detects these privilege-escalation techniques (plus wildcard, "
             "PassRole, AssumeRole-condition, and data-exfil rules):", ""]
    for p in ESCALATION_PRIMITIVES:
        lines.append(f"  - {p['id']}: {p['name']}  (requires: {', '.join(p['actions'])})")
    return _text("\n".join(lines))


TOOL_IMPL = {
    "audit_iam_policy": _tool_audit_iam_policy,
    "list_iam_rules": _tool_list_iam_rules,
}


def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def dispatch(msg: dict):
    """Handle one JSON-RPC message. Returns a response dict, or None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")
    is_notification = "id" not in msg

    if method == "initialize":
        client_ver = (msg.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION)
        return _ok(msg_id, {
            "protocolVersion": client_ver or PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "iam-sentinel", "version": config.ENGINE_VERSION},
        })

    if method in ("notifications/initialized", "initialized"):
        return None  # notification: no response

    if method == "ping":
        return _ok(msg_id, {})

    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})

    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        impl = TOOL_IMPL.get(name)
        if impl is None:
            return _err(msg_id, -32602, f"Unknown tool: {name}")
        try:
            return _ok(msg_id, impl(args))
        except Exception as e:  # tool errors are reported in-band, not as protocol errors
            log.exception("tool %s failed", name)
            return _ok(msg_id, _text(f"Tool '{name}' failed: {e}", is_error=True))

    if is_notification:
        return None
    return _err(msg_id, -32601, f"Method not found: {method}")


def serve_stdio():
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    logging.basicConfig(level="INFO", stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("IAM Sentinel MCP server ready on stdio (protocol %s)", PROTOCOL_VERSION)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(_err(None, -32700, "Parse error")) + "\n")
            sys.stdout.flush()
            continue
        response = dispatch(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    serve_stdio()
