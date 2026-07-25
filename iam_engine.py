"""
Deterministic AWS IAM policy analyzer — the flagship ground-truth engine.

This does NOT ask an LLM to find problems. It parses the policy document structurally
and applies a rule engine covering wildcards, NotAction+Allow traps, the canonical
privilege-escalation primitives (Rhino Security Labs / PMapper), toxic PassRole pairs,
unconditioned sts:AssumeRole, and data-exfiltration grants.

AWS only by design. Azure and GCP have their own engines (iam_engine_azure.py,
iam_engine_gcp.py); providers.py routes each document to the right one. Keeping this engine
provider-pure avoids cross-provider false positives (an AWS "*" must never emit Azure/GCP
findings). Pure stdlib — no ML deps.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from findings import Finding, ScanResult, Severity, Confidence

REF_RHINO = "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
REF_PMAPPER = "https://github.com/nccgroup/PMapper"
REF_AWS_PASSROLE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"

# --- Privilege-escalation primitives (AWS) -------------------------------------------
ESCALATION_PRIMITIVES: list[dict[str, Any]] = [
    {"id": "IAM.ESC_ATTACH_USER_POLICY", "actions": ["iam:AttachUserPolicy"],
     "name": "Attach arbitrary managed policy to a user (attach AdministratorAccess)"},
    {"id": "IAM.ESC_ATTACH_ROLE_POLICY", "actions": ["iam:AttachRolePolicy"],
     "name": "Attach arbitrary managed policy to a role"},
    {"id": "IAM.ESC_ATTACH_GROUP_POLICY", "actions": ["iam:AttachGroupPolicy"],
     "name": "Attach arbitrary managed policy to a group"},
    {"id": "IAM.ESC_PUT_USER_POLICY", "actions": ["iam:PutUserPolicy"],
     "name": "Write an inline admin policy onto a user"},
    {"id": "IAM.ESC_PUT_ROLE_POLICY", "actions": ["iam:PutRolePolicy"],
     "name": "Write an inline admin policy onto a role"},
    {"id": "IAM.ESC_PUT_GROUP_POLICY", "actions": ["iam:PutGroupPolicy"],
     "name": "Write an inline admin policy onto a group"},
    {"id": "IAM.ESC_CREATE_POLICY_VERSION", "actions": ["iam:CreatePolicyVersion"],
     "name": "Create a new default policy version granting more access"},
    {"id": "IAM.ESC_SET_DEFAULT_POLICY_VERSION", "actions": ["iam:SetDefaultPolicyVersion"],
     "name": "Roll a managed policy back to a more-permissive existing version"},
    {"id": "IAM.ESC_CREATE_ACCESS_KEY", "actions": ["iam:CreateAccessKey"],
     "name": "Mint access keys for another (more privileged) user"},
    {"id": "IAM.ESC_CREATE_LOGIN_PROFILE", "actions": ["iam:CreateLoginProfile"],
     "name": "Set a console password on another user"},
    {"id": "IAM.ESC_UPDATE_LOGIN_PROFILE", "actions": ["iam:UpdateLoginProfile"],
     "name": "Reset another user's console password"},
    {"id": "IAM.ESC_ADD_USER_TO_GROUP", "actions": ["iam:AddUserToGroup"],
     "name": "Add self to a privileged group"},
    {"id": "IAM.ESC_UPDATE_ASSUME_ROLE_POLICY", "actions": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
     "name": "Rewrite a role's trust policy, then assume it"},
    {"id": "IAM.ESC_PASSROLE_EC2", "actions": ["iam:PassRole", "ec2:RunInstances"],
     "name": "Launch EC2 with a privileged instance profile (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_LAMBDA", "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
     "name": "Create+invoke a Lambda running as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_LAMBDA_EVENT", "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
     "name": "Create a Lambda + event-source mapping as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_GLUE", "actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
     "name": "Create a Glue dev endpoint running as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_CLOUDFORMATION", "actions": ["iam:PassRole", "cloudformation:CreateStack"],
     "name": "Deploy a CloudFormation stack as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_DATAPIPELINE", "actions": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"],
     "name": "Run a Data Pipeline as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_SAGEMAKER", "actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
     "name": "Run a SageMaker notebook as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_CODEBUILD", "actions": ["iam:PassRole", "codebuild:StartBuild"],
     "name": "Start a CodeBuild build with a privileged service role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_ECS", "actions": ["iam:PassRole", "ecs:RunTask"],
     "name": "Run an ECS task with a privileged task execution role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_STEPFUNCTIONS", "actions": ["iam:PassRole", "states:CreateStateMachine"],
     "name": "Create a Step Functions state machine with a privileged execution role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_BATCH", "actions": ["iam:PassRole", "batch:SubmitJob"],
     "name": "Submit an AWS Batch job with a privileged execution role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_SSM", "actions": ["iam:PassRole", "ssm:SendCommand"],
     "name": "Send SSM commands to an instance with an attached privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_EMR", "actions": ["iam:PassRole", "elasticmapreduce:RunJobFlow"],
     "name": "Launch an EMR cluster with a privileged job flow role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_WORKSPACES", "actions": ["iam:PassRole", "workspaces:CreateWorkspaces"],
     "name": "Create WorkSpaces with a privileged execution role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_DATASYNC", "actions": ["iam:PassRole", "datasync:CreateTask"],
     "name": "Create DataSync task executing as a privileged role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_APPGATEWAY", "actions": ["iam:PassRole", "apigateway:POST"],
     "name": "Deploy API Gateway with a privileged execution role (PassRole)"},
    {"id": "IAM.ESC_PASSROLE_COGNITO", "actions": ["iam:PassRole", "cognito-idp:CreateUserPool"],
     "name": "Create Cognito user pool with a privileged execution role (PassRole)"},
]

EXFIL_ACTIONS = [
    "s3:GetObject", "s3:*", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:*",
    "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
    "kms:Decrypt", "rds:DownloadDBLogFilePortion",
]

FULL_ADMIN_ACTIONS = ["*", "iam:*", "sts:*"]


def _load_custom_primitives() -> None:
    """Append customer/vendor-defined escalation rules from a JSON file — no code change.

    Set CUSTOM_RULES_FILE, or drop a `custom_rules.json` next to this module. Format:
      {"escalation_primitives": [{"id": "IAM.ESC_MY_RULE", "actions": ["svc:Action1","svc:Action2"],
                                  "name": "human description"}]}
    This makes "custom rules" a config drop-in instead of an engineering task.
    """
    import json as _json
    import os as _os
    path = _os.getenv("CUSTOM_RULES_FILE", _os.path.join(_os.path.dirname(__file__), "custom_rules.json"))
    if not _os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _json.load(f)
        for e in data.get("escalation_primitives", []):
            if e.get("id") and e.get("actions"):
                ESCALATION_PRIMITIVES.append(
                    {"id": e["id"], "actions": list(e["actions"]), "name": e.get("name", e["id"])})
    except Exception as _e:  # never let a bad custom-rules file break the engine
        import logging
        logging.getLogger("iam-sentinel.engine").warning("custom rules not loaded: %s", _e)


_load_custom_primitives()


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _action_matches(granted_patterns: list[str], needed: str) -> bool:
    """True if any granted action pattern (supports IAM '*' globs) covers `needed`."""
    needed_l = needed.lower()
    for pat in granted_patterns:
        p = pat.lower()
        if p == "*":
            return True
        if fnmatch.fnmatch(needed_l, p):
            return True
    return False


def analyze_iam_policy(policy: dict, target: str = "pasted policy") -> ScanResult:
    """Run the deterministic rule engine over an AWS IAM policy document."""
    result = ScanResult(domain="iam", target=target)

    statements = _as_list(policy.get("Statement"))
    if not statements:
        result.parse_errors.append(
            "No 'Statement' array found — this may not be an AWS IAM identity/resource policy."
        )
        return result

    all_allowed_patterns: list[str] = []

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            result.parse_errors.append(f"Statement[{idx}] is not an object; skipped.")
            continue

        sid = stmt.get("Sid") or f"Statement[{idx}]"
        effect = str(stmt.get("Effect", "")).lower()
        actions = [str(a) for a in _as_list(stmt.get("Action"))]
        not_actions = [str(a) for a in _as_list(stmt.get("NotAction"))]
        resources = [str(r) for r in _as_list(stmt.get("Resource"))]
        has_condition = bool(stmt.get("Condition"))
        principals = stmt.get("Principal")

        if effect == "allow":
            all_allowed_patterns.extend(actions)

        # Allow + Action "*" (full admin)
        if effect == "allow" and any(a == "*" for a in actions):
            result.add(Finding(
                rule_id="IAM.WILDCARD_ACTION_ALL",
                title="Statement allows ALL actions (Action: \"*\")",
                severity=Severity.CRITICAL, domain="iam",
                description=f"{sid} grants Effect=Allow with Action \"*\", i.e. full administrative access.",
                evidence='"Action": "*"', location=sid,
                remediation_hint="Replace \"*\" with the explicit, minimal set of actions the principal needs.",
                references=[REF_PMAPPER]))

        # Allow + service-level wildcard (e.g. s3:*, iam:*)
        for a in actions:
            if effect == "allow" and a.endswith(":*"):
                sev = Severity.CRITICAL if a.lower() in ("iam:*", "sts:*") else Severity.HIGH
                result.add(Finding(
                    rule_id="IAM.WILDCARD_ACTION_SERVICE",
                    title=f"Service-wide wildcard action: {a}",
                    severity=sev, domain="iam",
                    description=f"{sid} grants every action in a service via '{a}'.",
                    evidence=f'"Action": "{a}"', location=sid,
                    remediation_hint=f"Enumerate only the specific {a.split(':')[0]} actions required instead of '{a}'."))

        # Allow + Resource "*" on scoped actions
        if effect == "allow" and any(r == "*" for r in resources) and actions and not any(a == "*" for a in actions):
            result.add(Finding(
                rule_id="IAM.WILDCARD_RESOURCE",
                title="Actions granted on all resources (Resource: \"*\")",
                severity=Severity.HIGH, domain="iam",
                description=f"{sid} applies its actions to every resource (Resource \"*\") with no scoping.",
                evidence='"Resource": "*"', location=sid, confidence=Confidence.FIRM,
                remediation_hint="Scope Resource to specific ARNs, or add a Condition constraining the resource set."))

        # NotAction + Allow (inversion trap)
        if effect == "allow" and not_actions:
            result.add(Finding(
                rule_id="IAM.NOTACTION_ALLOW",
                title="Allow combined with NotAction grants everything except a denylist",
                severity=Severity.HIGH, domain="iam",
                description=(f"{sid} uses Effect=Allow with NotAction {not_actions}. This grants ALL actions "
                             "except those listed — new AWS actions are auto-granted and it is easy to under-scope."),
                evidence=f'"NotAction": {not_actions}', location=sid, confidence=Confidence.FIRM,
                remediation_hint="Prefer an explicit Action allowlist; reserve NotAction for Deny statements."))

        # Over-broad trust / resource policy principal
        if effect == "allow" and principals is not None:
            flat = []
            if isinstance(principals, dict):
                for v in principals.values():
                    flat.extend(_as_list(v))
            else:
                flat.extend(_as_list(principals))
            if any(str(p) == "*" for p in flat):
                sev = Severity.MEDIUM if has_condition else Severity.CRITICAL
                result.add(Finding(
                    rule_id="IAM.WILDCARD_PRINCIPAL",
                    title="Resource/trust policy allows any principal (Principal: \"*\")",
                    severity=sev, domain="iam",
                    description=(f"{sid} allows Principal \"*\""
                                 + (" but is constrained by a Condition." if has_condition
                                    else " with NO Condition — this is world-accessible.")),
                    evidence='"Principal": "*"', location=sid,
                    confidence=Confidence.CERTAIN if not has_condition else Confidence.TENTATIVE,
                    remediation_hint="Restrict Principal to specific account/role ARNs, and add Conditions (aws:SourceArn, aws:PrincipalOrgID)."))

        # sts:AssumeRole without a Condition
        if effect == "allow" and _action_matches(actions, "sts:AssumeRole") and not has_condition:
            result.add(Finding(
                rule_id="IAM.ASSUMEROLE_NO_CONDITION",
                title="sts:AssumeRole granted without any Condition",
                severity=Severity.MEDIUM, domain="iam",
                description=f"{sid} allows sts:AssumeRole with no Condition (e.g. no MFA / ExternalId / source constraint).",
                evidence='"Action": "sts:AssumeRole" (no Condition)', location=sid, confidence=Confidence.FIRM,
                remediation_hint="Add Conditions such as aws:MultiFactorAuthPresent, sts:ExternalId, or aws:PrincipalOrgID."))

        # iam:PassRole scoped to "*"
        if effect == "allow" and _action_matches(actions, "iam:PassRole") and any(r == "*" for r in resources):
            result.add(Finding(
                rule_id="IAM.PASSROLE_WILDCARD",
                title="iam:PassRole allowed on all roles (Resource: \"*\")",
                severity=Severity.HIGH, domain="iam",
                description=(f"{sid} allows iam:PassRole on Resource \"*\". Combined with a compute-launch "
                             "action this lets the principal run workloads as ANY role in the account."),
                evidence='"Action": "iam:PassRole", "Resource": "*"', location=sid,
                remediation_hint="Restrict PassRole to specific role ARNs and add iam:PassedToService conditions.",
                references=[REF_AWS_PASSROLE]))

    # If the policy grants a global "*" action, the granular escalation / admin / exfil rules
    # below are redundant symptoms of the same root cause (WILDCARD_ACTION_ALL). Suppress the
    # noise. The granular rules matter most when a policy LOOKS scoped but still escalates.
    if any(p == "*" for p in all_allowed_patterns):
        result.stats = {
            "statement_count": len(statements),
            "allowed_action_patterns": sorted(set(all_allowed_patterns)),
            "note": "Global Action \"*\" present; granular escalation/exfil rules suppressed as redundant.",
        }
        return result

    # Cross-statement privilege-escalation primitives
    for prim in ESCALATION_PRIMITIVES:
        if all(_action_matches(all_allowed_patterns, act) for act in prim["actions"]):
            result.add(Finding(
                rule_id=prim["id"],
                title=f"Privilege-escalation path: {prim['name']}",
                severity=Severity.CRITICAL, domain="iam",
                description=("The policy grants the full action set required for a known privilege-escalation "
                             f"technique: {prim['actions']}. An attacker with this identity can escalate privilege."),
                evidence=" + ".join(prim["actions"]), location="cross-statement", confidence=Confidence.FIRM,
                remediation_hint="Remove or tightly scope (by Resource + Condition) at least one action in the chain to break it.",
                references=[REF_RHINO]))

    # Admin-equivalent single grants
    for admin_act in FULL_ADMIN_ACTIONS:
        if admin_act != "*" and _action_matches(all_allowed_patterns, admin_act):
            result.add(Finding(
                rule_id="IAM.ADMIN_EQUIVALENT",
                title=f"Admin-equivalent grant: {admin_act}",
                severity=Severity.CRITICAL, domain="iam",
                description=f"The policy grants '{admin_act}', which is effectively full control of that service's security surface.",
                evidence=f'"Action": "{admin_act}"', location="cross-statement",
                remediation_hint=f"Replace '{admin_act}' with the specific actions actually required."))

    # Data-exfiltration-capable grants on "*"
    doc_has_star_resource = any(
        str(s.get("Effect", "")).lower() == "allow" and any(str(r) == "*" for r in _as_list(s.get("Resource")))
        for s in statements if isinstance(s, dict))
    if doc_has_star_resource:
        for exfil in EXFIL_ACTIONS:
            if _action_matches(all_allowed_patterns, exfil):
                result.add(Finding(
                    rule_id="IAM.DATA_EXFIL_CAPABLE",
                    title=f"Broad data-read grant enables exfiltration: {exfil}",
                    severity=Severity.HIGH, domain="iam",
                    description=f"'{exfil}' is granted alongside Resource \"*\", allowing bulk read/exfiltration of data.",
                    evidence=f'"Action": "{exfil}" with Resource "*"', location="cross-statement", confidence=Confidence.FIRM,
                    remediation_hint="Scope the data-plane actions to specific bucket/table/secret ARNs."))
                break

    result.stats = {
        "statement_count": len(statements),
        "allowed_action_patterns": sorted(set(all_allowed_patterns)),
    }
    return result


if __name__ == "__main__":
    import json
    import sys
    pol = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {
        "Statement": [
            {"Sid": "Wild", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "Pass", "Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"},
        ]}
    print(analyze_iam_policy(pol).to_json())
