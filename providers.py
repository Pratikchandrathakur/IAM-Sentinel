"""
Multi-cloud provider dispatcher.

Routes an IAM/RBAC document to the right deterministic engine (AWS / Azure / GCP), with
auto-detection from the document shape. The Finding/ScanResult schema is provider-agnostic,
so downstream (store, API, MCP, LLM narrative) is unchanged across clouds.
"""

from iam_engine import analyze_iam_policy as _aws
from iam_engine_azure import analyze_azure_role as _azure, looks_like_azure
from iam_engine_gcp import analyze_gcp_policy as _gcp, looks_like_gcp

PROVIDERS = ("aws", "azure", "gcp")


def detect_provider(policy: dict) -> str:
    """Best-effort provider detection from document structure."""
    if not isinstance(policy, dict):
        return "aws"
    if looks_like_gcp(policy):
        return "gcp"
    if looks_like_azure(policy):
        return "azure"
    # AWS IAM policies have a Statement array (identity/resource policy).
    if "Statement" in policy:
        return "aws"
    # Fall back to AWS (most common); the engine will emit a parse error if wrong.
    return "aws"


def analyze_policy(policy: dict, provider: str = "auto", target: str = "pasted policy"):
    """Analyze a policy with the appropriate provider engine. Returns a ScanResult."""
    prov = (provider or "auto").lower()
    if prov == "auto":
        prov = detect_provider(policy)
    if prov == "azure":
        scan = _azure(policy, target=target)
    elif prov == "gcp":
        scan = _gcp(policy, target=target)
    else:
        prov = "aws"
        scan = _aws(policy, target=target)
    scan.stats = {**(scan.stats or {}), "provider": prov}
    return scan, prov
