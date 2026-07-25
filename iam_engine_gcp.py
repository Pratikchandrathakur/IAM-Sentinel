"""
Deterministic GCP IAM analyzer.

Parses a GCP IAM policy (getIamPolicy output: {"bindings":[{"role":..., "members":[...]}]})
or a custom role definition ({"includedPermissions":[...]}), and flags:
  * primitive roles (roles/owner, roles/editor) — over-broad by design
  * public exposure: allUsers / allAuthenticatedUsers members
  * privilege-escalation roles/permissions: setIamPolicy, serviceAccountTokenCreator,
    serviceAccountUser (actAs), serviceAccountKeyAdmin, iam.roles.update
  * broadly-granted service account impersonation

Pure stdlib; emits the shared Finding/ScanResult schema.
"""

from __future__ import annotations

from findings import Finding, ScanResult, Severity, Confidence

REF = "https://cloud.google.com/iam/docs/understanding-roles"
REF_ESC = "https://cloud.google.com/iam/docs/privilege-escalation"

PRIMITIVE_ROLES = {
    "roles/owner": ("Owner primitive role (full control incl. IAM)", Severity.CRITICAL),
    "roles/editor": ("Editor primitive role (broad write across all services)", Severity.HIGH),
}

# roles that directly enable privilege escalation
ESC_ROLES = {
    "roles/iam.securityAdmin": "Manage IAM policy (grant any role) — setIamPolicy",
    "roles/iam.serviceAccountTokenCreator": "Mint access tokens for service accounts (impersonation)",
    "roles/iam.serviceAccountUser": "actAs service accounts (run workloads as their identity)",
    "roles/iam.serviceAccountKeyAdmin": "Create service-account keys (persistent impersonation)",
    "roles/iam.roleAdmin": "Create/modify custom roles to grant more access",
    "roles/resourcemanager.projectIamAdmin": "Set project IAM policy (grant any role)",
    "roles/owner": "Owner (setIamPolicy + everything)",
}

# custom-role permissions that enable escalation
ESC_PERMISSIONS = {
    "resourcemanager.projects.setIamPolicy": "Set project IAM policy (grant self any role)",
    "iam.serviceAccounts.actAs": "actAs a service account",
    "iam.serviceAccounts.getAccessToken": "Impersonate a service account (token)",
    "iam.serviceAccounts.getOpenIdToken": "Impersonate a service account (OIDC token)",
    "iam.serviceAccountKeys.create": "Create service-account keys (persistence)",
    "iam.roles.update": "Modify custom roles to add permissions",
    "iam.roles.create": "Create custom roles",
}

PUBLIC_MEMBERS = {"allusers": "allUsers", "allauthenticatedusers": "allAuthenticatedUsers"}


def looks_like_gcp(policy: dict) -> bool:
    return "bindings" in policy or "includedPermissions" in policy


def analyze_gcp_policy(policy: dict, target: str = "gcp policy") -> ScanResult:
    result = ScanResult(domain="iam", target=target)
    result.stats = {"provider": "gcp"}

    bindings = policy.get("bindings")
    included = policy.get("includedPermissions")

    if bindings is None and included is None:
        result.parse_errors.append("No 'bindings' or 'includedPermissions' — not a GCP IAM policy/role?")
        return result

    # --- IAM policy bindings ---
    for b in (bindings or []):
        if not isinstance(b, dict):
            continue
        role = str(b.get("role", ""))
        members = [str(m) for m in b.get("members", [])]
        has_condition = bool(b.get("condition"))

        # public exposure
        for m in members:
            key = m.strip().lower()
            if key in PUBLIC_MEMBERS:
                sev = Severity.HIGH if has_condition else Severity.CRITICAL
                result.add(Finding(
                    rule_id="GCP.PUBLIC_MEMBER",
                    title=f"Role granted to the public ({PUBLIC_MEMBERS[key]})",
                    severity=sev, domain="iam",
                    description=f"'{role}' is granted to {PUBLIC_MEMBERS[key]}"
                                + (" (with an IAM condition)." if has_condition else " — anyone on the internet."),
                    evidence=f'{{"role":"{role}","members":["{m}"]}}', location=role,
                    confidence=Confidence.CERTAIN if not has_condition else Confidence.FIRM,
                    remediation_hint="Remove allUsers/allAuthenticatedUsers; grant to specific principals.",
                    references=[REF], metadata={"provider": "gcp"}))

        # primitive roles
        if role in PRIMITIVE_ROLES:
            desc, sev = PRIMITIVE_ROLES[role]
            result.add(Finding(
                rule_id="GCP.PRIMITIVE_ROLE", title=f"Primitive role in use: {role}",
                severity=sev, domain="iam",
                description=f"{desc}. Granted to {members}.",
                evidence=f'"role": "{role}"', location=role,
                remediation_hint="Replace primitive roles with predefined or custom least-privilege roles.",
                references=[REF], metadata={"provider": "gcp"}))
        elif role in ESC_ROLES:
            result.add(Finding(
                rule_id="GCP.ESC_ROLE", title=f"Privilege-escalation role: {role}",
                severity=Severity.CRITICAL, domain="iam",
                description=f"{ESC_ROLES[role]}. Granted to {members}.",
                evidence=f'"role": "{role}"', location=role, confidence=Confidence.FIRM,
                remediation_hint="Grant this only to break-glass identities, scoped and audited.",
                references=[REF_ESC], metadata={"provider": "gcp"}))

    # --- custom role permissions ---
    for perm in (included or []):
        p = str(perm)
        if p in ESC_PERMISSIONS:
            result.add(Finding(
                rule_id="GCP.ESC_PERMISSION", title=f"Escalation-enabling permission: {p}",
                severity=Severity.CRITICAL, domain="iam",
                description=f"Custom role includes '{p}': {ESC_PERMISSIONS[p]}.",
                evidence=p, location="custom role", confidence=Confidence.FIRM,
                remediation_hint="Remove or tightly scope this permission; it enables privilege escalation.",
                references=[REF_ESC], metadata={"provider": "gcp"}))
        if p.endswith(".*") or p == "*":
            result.add(Finding(
                rule_id="GCP.WILDCARD_PERMISSION", title=f"Wildcard permission in custom role: {p}",
                severity=Severity.HIGH, domain="iam",
                description=f"Custom role includes wildcard permission '{p}'.",
                evidence=p, location="custom role",
                remediation_hint="Enumerate explicit permissions instead of wildcards.",
                metadata={"provider": "gcp"}))

    result.stats["provider"] = "gcp"
    return result
