"""
Deterministic remediation report — NO LLM, NO external dependency.

This makes the "remediation narrative" a first-class, offline feature. It composes a clear,
actionable report purely from the verified findings (severities + evidence + the engine's
own fix hints) plus a least-privilege guidance section. The optional Ollama/LLM narrative
becomes pure polish on top — the product is fully useful with zero models installed.
"""

from findings import ScanResult

# Provider-specific least-privilege skeletons offered when the policy is over-broad.
_SKELETON = {
    "aws": (
        '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n'
        '      "Sid": "LeastPrivilege",\n      "Effect": "Allow",\n'
        '      "Action": ["service:SpecificAction"],\n'
        '      "Resource": ["arn:aws:service:region:account:resource/specific"],\n'
        '      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxx"}}\n'
        '    }\n  ]\n}'
    ),
    "azure": (
        '{\n  "properties": {\n    "roleName": "LeastPrivilegeRole",\n'
        '    "permissions": [{ "actions": ["Microsoft.Service/resource/read"], "notActions": [] }],\n'
        '    "assignableScopes": ["/subscriptions/<sub>/resourceGroups/<rg>"]\n  }\n}'
    ),
    "gcp": (
        '{\n  "bindings": [\n    { "role": "roles/service.specificViewer",\n'
        '      "members": ["serviceAccount:app@project.iam.gserviceaccount.com"] }\n  ]\n}'
    ),
}


def build_report(scan: ScanResult, provider: str = "aws") -> str:
    """Return a deterministic markdown remediation report for a ScanResult."""
    findings = scan.deduped()
    counts = scan.severity_counts()
    lines = [
        f"# IAM Sentinel — Remediation Report ({provider.upper()})",
        f"**Overall severity:** {scan.highest_severity.value}  ·  "
        f"**Findings:** {len(findings)}  ·  **Counts:** {counts}  ·  "
        f"**Ruleset:** {scan.ruleset_version or 'n/a'}",
        "",
    ]

    if not findings:
        lines += [
            "## ✅ PASS",
            "No privilege-escalation paths or over-permission were detected by the deterministic "
            "rule engine. The policy scoping looks sound for the rules in this pack.",
        ]
        return "\n".join(lines)

    lines.append("## Findings & fixes")
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. [{f.severity.value}] `{f.rule_id}` — {f.title}")
        lines.append(f"- **What was observed:** {f.description}")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence}`")
        if f.location:
            lines.append(f"- **Location:** {f.location}")
        if f.remediation_hint:
            lines.append(f"- **Fix:** {f.remediation_hint}")
        if f.references:
            lines.append(f"- **Reference:** {f.references[0]}")
        lines.append("")

    # Deduplicated, prioritized remediation checklist from the fix hints.
    hints = []
    for f in findings:
        if f.remediation_hint and f.remediation_hint not in hints:
            hints.append(f.remediation_hint)
    if hints:
        lines.append("## Least-privilege checklist")
        for h in hints:
            lines.append(f"- [ ] {h}")
        lines.append("")

    # Offer a skeleton only when there is real over-permission to rewrite.
    if any(f.severity.value in ("CRITICAL", "HIGH") for f in findings):
        lines.append("## Suggested least-privilege skeleton")
        lines.append("```json")
        lines.append(_SKELETON.get(provider, _SKELETON["aws"]))
        lines.append("```")
        lines.append("Replace the placeholders with the specific actions, resource ARNs/scopes, "
                     "and conditions your workload actually needs.")

    return "\n".join(lines)
