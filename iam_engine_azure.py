"""
Deterministic Azure RBAC analyzer.

Parses Azure role definitions / custom roles and flags privilege-escalation and over-broad
grants. Key Azure escalation primitives:
  * Microsoft.Authorization/roleAssignments/write  -> assign yourself any role (the classic
    Azure priv-esc; equal to Owner if scoped broadly)
  * Microsoft.Authorization/*                       -> full RBAC control
  * Microsoft.Authorization/elevateAccess/action    -> elevate to User Access Administrator at root
  * actions "*"                                     -> Owner-equivalent
  * dataActions "*"                                 -> full data-plane
  * assignableScopes "/" or a bare subscription root -> tenant/subscription-wide blast radius

Accepts either a full role definition ({"properties":{"permissions":[...]}}) or a bare
permissions object. Pure stdlib; emits the shared Finding/ScanResult schema.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from findings import Finding, ScanResult, Severity, Confidence

REF = "https://learn.microsoft.com/azure/role-based-access-control/role-definitions"


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _matches(patterns, needed) -> bool:
    n = needed.lower()
    return any(p.lower() == "*" or fnmatch.fnmatch(n, p.lower()) for p in patterns)


def _extract(policy: dict):
    """Return (permissions_list, assignable_scopes, role_name)."""
    props = policy.get("properties", policy)
    perms = props.get("permissions", [])
    if isinstance(perms, dict):
        perms = [perms]
    scopes = [str(s) for s in _as_list(props.get("assignableScopes"))]
    name = props.get("roleName") or props.get("name") or policy.get("name") or "custom role"
    return perms, scopes, name


def looks_like_azure(policy: dict) -> bool:
    props = policy.get("properties", policy)
    if "permissions" in props and isinstance(props.get("permissions"), (list, dict)):
        blob = str(props).lower()
        return "actions" in blob or "assignablescopes" in str(props).lower() or "microsoft." in blob
    return False


def analyze_azure_role(policy: dict, target: str = "azure role") -> ScanResult:
    result = ScanResult(domain="iam", target=target)
    result.stats = {"provider": "azure"}

    perms, scopes, role_name = _extract(policy)
    if not perms:
        result.parse_errors.append("No 'permissions' found — not an Azure role definition?")
        return result

    all_actions, all_data_actions = [], []
    for block in perms:
        if not isinstance(block, dict):
            continue
        actions = [str(a) for a in _as_list(block.get("actions"))]
        data_actions = [str(a) for a in _as_list(block.get("dataActions"))]
        not_actions = [str(a) for a in _as_list(block.get("notActions"))]
        all_actions.extend(actions)
        all_data_actions.extend(data_actions)

        if any(a == "*" for a in actions):
            result.add(Finding(
                rule_id="AZ.WILDCARD_ACTION_ALL", title="Role grants ALL control-plane actions (actions: \"*\")",
                severity=Severity.CRITICAL, domain="iam",
                description=f"Role '{role_name}' grants actions \"*\" — Owner-equivalent control.",
                evidence='"actions": ["*"]', location=role_name,
                remediation_hint="Enumerate only the specific Microsoft.* actions required.",
                references=[REF], metadata={"provider": "azure"}))

        if any(a == "*" for a in data_actions):
            result.add(Finding(
                rule_id="AZ.WILDCARD_DATAACTION_ALL", title="Role grants ALL data-plane actions (dataActions: \"*\")",
                severity=Severity.HIGH, domain="iam",
                description=f"Role '{role_name}' grants dataActions \"*\" — full data-plane access (blobs, secrets, etc.).",
                evidence='"dataActions": ["*"]', location=role_name,
                remediation_hint="Scope dataActions to the specific resource operations required.",
                metadata={"provider": "azure"}))

        if not_actions and any(a == "*" for a in actions):
            result.add(Finding(
                rule_id="AZ.NOTACTIONS_TRAP", title="actions:* softened only by notActions",
                severity=Severity.HIGH, domain="iam",
                description=f"Role '{role_name}' grants everything except a notActions denylist; new Azure "
                            "actions are auto-granted.",
                evidence=f'"notActions": {not_actions}', location=role_name,
                confidence=Confidence.FIRM,
                remediation_hint="Prefer an explicit actions allowlist over actions:* + notActions.",
                metadata={"provider": "azure"}))

    # --- escalation primitives (control plane) ---
    esc = [
        ("AZ.ESC_ROLE_ASSIGNMENT_WRITE", "Microsoft.Authorization/roleAssignments/write",
         "Assign any role to any principal (self-escalation to Owner)"),
        ("AZ.ESC_AUTHORIZATION_ALL", "Microsoft.Authorization/*",
         "Full RBAC control (create roles + assignments)"),
        ("AZ.ESC_ELEVATE_ACCESS", "Microsoft.Authorization/elevateAccess/action",
         "Elevate to User Access Administrator at root scope"),
        ("AZ.ESC_ROLE_DEFINITION_WRITE", "Microsoft.Authorization/roleDefinitions/write",
         "Create/modify custom role definitions to grant more access"),
        ("AZ.ESC_MANAGED_IDENTITY_ASSIGN", "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action",
         "Assign a managed identity to compute (identity abuse, PassRole-like)"),
        ("AZ.ESC_DEPLOYMENTS_WRITE", "Microsoft.Resources/deployments/write",
         "Deploy ARM templates that run as a privileged identity"),
    ]
    for rule_id, action, name in esc:
        if _matches(all_actions, action):
            result.add(Finding(
                rule_id=rule_id, title=f"Privilege escalation: {name}",
                severity=Severity.CRITICAL, domain="iam",
                description=f"Role '{role_name}' grants '{action}', enabling: {name}.",
                evidence=action, location=role_name, confidence=Confidence.FIRM,
                remediation_hint="Remove this action or constrain the role's assignableScopes tightly.",
                references=[REF], metadata={"provider": "azure"}))

    # --- scope breadth ---
    for scope in scopes:
        if scope == "/" or scope == "":
            result.add(Finding(
                rule_id="AZ.SCOPE_ROOT", title="Role assignable at tenant root scope (\"/\")",
                severity=Severity.HIGH, domain="iam",
                description=f"Role '{role_name}' is assignable at '/' (tenant root) — maximum blast radius.",
                evidence=f'"assignableScopes": ["{scope}"]', location=role_name,
                remediation_hint="Restrict assignableScopes to a specific resource group or resource.",
                metadata={"provider": "azure"}))
        elif fnmatch.fnmatch(scope, "/subscriptions/*") and scope.count("/") == 2:
            result.add(Finding(
                rule_id="AZ.SCOPE_SUBSCRIPTION", title="Role assignable across an entire subscription",
                severity=Severity.MEDIUM, domain="iam",
                description=f"Role '{role_name}' is assignable across a full subscription ({scope}).",
                evidence=f'"assignableScopes": ["{scope}"]', location=role_name,
                confidence=Confidence.FIRM,
                remediation_hint="Prefer resource-group or resource scope where practical.",
                metadata={"provider": "azure"}))

    result.stats["provider"] = "azure"
    return result
