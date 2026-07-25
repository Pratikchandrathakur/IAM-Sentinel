"""
IAM Sentinel — grounded analysis.

Pipeline:
  1. Deterministic rule engine parses the policy and emits verified Findings (ground truth).
  2. (optional) A local LLM narrates + remediates ONLY those findings — it cannot invent new
     ones. If the model is unavailable or disabled, findings still return, clearly flagged.

The deterministic result is the product; the narrative is polish.
"""

import json

import config
from findings import sha256_hex, utc_now_iso
from providers import analyze_policy
from llm_client import LLMClient, LLMUnavailable

GROUNDED_SYSTEM_PROMPT = (
    "You are a Cloud Security & IAM Governance Lead. A deterministic rule engine has ALREADY "
    "parsed the cloud IAM/RBAC policy and produced the verified findings below. Explain, "
    "prioritize, and remediate THOSE findings only.\n"
    "STRICT RULES:\n"
    "- Treat the DETERMINISTIC FINDINGS as ground truth. Do NOT invent vulnerabilities not "
    "supported by the findings or plainly visible in the policy JSON.\n"
    "- If the findings list is empty, say the policy passed automated checks; do not fabricate.\n"
    "- Refer to findings by rule_id so each claim is traceable to the engine."
)

LLM_UNAVAILABLE_NOTICE = (
    "⚠️ LLM narrative unavailable (model backend error). The deterministic findings above are "
    "authoritative and complete on their own."
)

LLM_DISABLED_NOTICE = (
    "ℹ️ LLM narrative disabled for this deployment. The deterministic findings above are the "
    "authoritative result."
)


def analyze(policy_data: dict, target: str = "pasted policy", model: str = None,
            backend: str = "ollama", structured: bool = True, provider: str = "auto"):
    """Run deterministic IAM/RBAC analysis + optional grounded LLM narrative.

    `provider` is one of auto|aws|azure|gcp. Returns a dict: {scan, report,
    llm_narrative_ok, provider}. Set structured=False to get only the narrative string.
    """
    scan, resolved_provider = analyze_policy(policy_data, provider=provider, target=target)
    policy_str = json.dumps(policy_data, indent=2, sort_keys=True)
    scan.engine_version = config.ENGINE_VERSION
    scan.ruleset_version = config.RULESET_VERSION
    scan.scanned_at = utc_now_iso()
    scan.artifact_sha256 = sha256_hex(policy_str)

    iac = {"aws": "an `aws_iam_policy` (Terraform)", "azure": "an `azurerm_role_definition` (Terraform)",
           "gcp": "a `google_project_iam_custom_role` / binding (Terraform)"}.get(resolved_provider,
                                                                                   "the appropriate IaC")
    llm_ok = True
    if not config.LLM_NARRATIVE_ENABLED:
        narrative, llm_ok = LLM_DISABLED_NOTICE, True
    else:
        prompt = (
            f"{resolved_provider.upper()} IAM/RBAC policy under review:\n```json\n{policy_str}\n```\n\n"
            f"DETERMINISTIC FINDINGS (ground truth — {scan.finding_count} issue(s); "
            f"highest severity {scan.highest_severity.value}; counts {scan.severity_counts()}):\n"
            f"{scan.to_evidence_block()}\n\n"
            "Produce a report with:\n"
            "1. **Risk Summary** — overall severity + 1-line impact.\n"
            "2. **Finding Walkthrough** — per finding (cite rule_id): why it is dangerous and the concrete attack.\n"
            "3. **Least-Privilege Refactor** — a complete corrected policy for this provider.\n"
            f"4. **IaC Remediation** — {iac} for the refactored policy.\n"
            "5. **Governance Hardening** — conditions / scope / MFA constraints relevant to the findings."
        )
        try:
            narrative = LLMClient(backend=backend).query(
                prompt=prompt, model=model, system_prompt=GROUNDED_SYSTEM_PROMPT)
        except LLMUnavailable:
            narrative, llm_ok = LLM_UNAVAILABLE_NOTICE, False

    if structured:
        return {"scan": scan.to_dict(), "report": narrative,
                "llm_narrative_ok": llm_ok, "provider": resolved_provider}
    return narrative


if __name__ == "__main__":
    import sys
    pol = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else {
        "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]
    }
    out = analyze(pol)
    print(json.dumps(out["scan"], indent=2))
    print("\n--- NARRATIVE ---\n", out["report"])
