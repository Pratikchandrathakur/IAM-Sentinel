"""
Terraform → IAM policy extractor.

Parses the JSON output of `terraform show -json <planfile>` (or `terraform plan -json`) and
pulls out the IAM/RBAC policies so IAM Sentinel's deterministic engines can audit them —
without ever parsing HCL. Parsing the *plan JSON* is more reliable than HCL because it
contains fully-resolved values (interpolations, locals, computed refs).

Supported resources:
  AWS   — aws_iam_policy / aws_iam_role_policy / aws_iam_user_policy / aws_iam_group_policy
          (attr `policy`), aws_iam_role (attr `assume_role_policy`)
  Azure — azurerm_role_definition (block `permissions`)
  GCP   — google_project_iam_custom_role (attr `permissions`),
          google_*_iam_binding / google_*_iam_member (role + members)

Returns a list of extracted policies, each: {name, provider, address, policy}
where `policy` is a dict ready for providers.analyze_policy(). Pure stdlib.
"""

from __future__ import annotations

import json
from typing import Any


def _walk_modules(module: dict):
    """Yield every resource dict from a plan's module tree (root + nested)."""
    for r in module.get("resources", []):
        yield r
    for child in module.get("child_modules", []):
        yield from _walk_modules(child)


def _iter_resources(plan: dict):
    """Yield (address, type, name, values) from planned_values or resource_changes."""
    pv = plan.get("planned_values", {})
    root = pv.get("root_module")
    if root:
        for r in _walk_modules(root):
            yield (r.get("address", r.get("name", "?")), r.get("type", ""),
                   r.get("name", ""), r.get("values", {}) or {})
    # Fallback / also cover resource_changes (create/update "after" state).
    for rc in plan.get("resource_changes", []):
        after = (rc.get("change", {}) or {}).get("after")
        if isinstance(after, dict):
            yield (rc.get("address", "?"), rc.get("type", ""), rc.get("name", ""), after)


def _load_json_policy(val: Any):
    if isinstance(val, dict):
        return val
    if isinstance(val, str) and val.strip().startswith("{"):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return None
    return None


def _azure_policy(values: dict) -> dict | None:
    perms = values.get("permissions")
    if not perms:
        return None
    blocks = perms if isinstance(perms, list) else [perms]
    norm = []
    for b in blocks:
        if isinstance(b, dict):
            norm.append({
                "actions": b.get("actions", []) or [],
                "notActions": b.get("not_actions", b.get("notActions", [])) or [],
                "dataActions": b.get("data_actions", b.get("dataActions", [])) or [],
            })
    scopes = values.get("assignable_scopes", values.get("assignableScopes", [])) or []
    return {"properties": {"roleName": values.get("name", "tf-role"),
                           "permissions": norm, "assignableScopes": scopes}}


def extract_policies(plan: dict) -> list[dict]:
    out: list[dict] = []
    seen = set()

    def add(name, provider, address, policy):
        if policy is None:
            return
        key = (address, json.dumps(policy, sort_keys=True))
        if key in seen:
            return
        seen.add(key)
        out.append({"name": name, "provider": provider, "address": address, "policy": policy})

    for address, rtype, name, values in _iter_resources(plan):
        # --- AWS ---
        if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            add(name, "aws", address, _load_json_policy(values.get("policy")))
        elif rtype == "aws_iam_role":
            add(f"{name} (trust)", "aws", address, _load_json_policy(values.get("assume_role_policy")))
        # --- Azure ---
        elif rtype == "azurerm_role_definition":
            add(name, "azure", address, _azure_policy(values))
        # --- GCP ---
        elif rtype == "google_project_iam_custom_role":
            perms = values.get("permissions") or []
            if perms:
                add(name, "gcp", address, {"includedPermissions": list(perms)})
        elif rtype.startswith("google_") and ("iam_binding" in rtype or "iam_member" in rtype):
            role = values.get("role")
            members = values.get("members") or ([values["member"]] if values.get("member") else [])
            if role:
                add(name, "gcp", address, {"bindings": [{"role": role, "members": members}]})

    return out


def extract_from_file(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        plan = json.load(f)
    return extract_policies(plan)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python terraform_extract.py <terraform-plan.json>")
        sys.exit(1)
    for p in extract_from_file(sys.argv[1]):
        print(f"{p['provider']:5s} {p['address']}")
