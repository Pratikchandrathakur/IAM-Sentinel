"""
IAM Sentinel — HTTP API.

Endpoints:
  GET  /                     health/attestation summary (HTML)
  GET  /api/health           liveness + attestation (versions, auth, offline, LLM reachability)
  GET  /api/readyz           readiness (engine + store), independent of LLM
  POST /api/audit/iam        deterministic audit (+ grounded narrative), persisted with provenance
  GET  /api/rules            the deterministic rule catalog
  GET  /api/scans            scan history (audit)
  GET  /api/scans/{id}       one scan with findings
  GET  /api/scans/diff/{d}   diff last two scans of a target (did remediation work?)
"""

import os
import json
import uuid
import logging

import uvicorn
import requests
from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

import config
import auth
import licensing
import metering
from analyzer import analyze
from store import get_store
from iam_engine import ESCALATION_PRIMITIVES
from providers import PROVIDERS

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("iam-sentinel.api")

for _w in config.validate_startup():
    log.warning("STARTUP: %s", _w)

# Load & log the active license once at startup.
LICENSE = licensing.load_active_license()
log.info("License: plan=%s customer=%s signed=%s expires=%s",
         LICENSE.plan, LICENSE.customer, LICENSE.signed, LICENSE.expires or "perpetual")

app = FastAPI(title=f"{config.PRODUCT_NAME} API", version=config.ENGINE_VERSION)

if config.CORS_ALLOW_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ALLOW_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Authorization", "Content-Type"],
    )

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def require_role(minimum: str):
    """FastAPI dependency factory: authenticate, then enforce an RBAC minimum role."""
    def _dep(request: Request,
             api_key: str = Security(_api_key_header),
             bearer: str = Security(_bearer_header)) -> auth.Principal:
        try:
            principal = auth.resolve_principal(api_key, bearer)
        except auth.AuthError as e:
            log.warning("AUTH DENIED request_id=%s path=%s reason=%s",
                        getattr(request.state, "request_id", "-"), request.url.path, e)
            raise HTTPException(status_code=e.status, detail=str(e))
        if not auth.has_role(principal.role, minimum):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{principal.role}' is insufficient; '{minimum}' or higher required.")
        request.state.principal = principal
        return principal
    return _dep


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    log.info("request_id=%s method=%s path=%s status=%s",
             request.state.request_id, request.method, request.url.path, response.status_code)
    return response


class IAMAuditRequest(BaseModel):
    policy_json: str
    provider: Optional[str] = "auto"          # auto | aws | azure | gcp
    target: Optional[str] = "pasted policy"
    model: Optional[str] = None
    backend: Optional[str] = "ollama"


@app.get("/", response_class=HTMLResponse)
def index():
    html_path = os.path.join(config.BASE_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return (
        f"<h1>{config.PRODUCT_NAME} {config.ENGINE_VERSION}</h1>"
        f"<p>Deterministic, local AWS IAM privilege-escalation auditor. "
        f"Ruleset {config.RULESET_VERSION}. See <code>/api/health</code> or <code>/pricing</code>.</p>"
    )


@app.get("/pricing", response_class=HTMLResponse)
def pricing():
    path = os.path.join(config.BASE_DIR, "pricing.html")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    raise HTTPException(status_code=404, detail="pricing.html not found.")


@app.get("/api/health")
def health():
    ollama_up = False
    try:
        tags_url = config.OLLAMA_API_URL.replace("/api/generate", "/api/tags")
        ollama_up = requests.get(tags_url, timeout=3).status_code == 200
    except Exception:
        ollama_up = False
    return {
        "status": "online",
        "product": config.PRODUCT_NAME,
        "engine_version": config.ENGINE_VERSION,
        "ruleset_version": config.RULESET_VERSION,
        "providers": list(PROVIDERS),
        "auth_enabled": config.AUTH_ENABLED,
        "sso_enabled": config.SSO_ENABLED,
        "tls_enabled": config.TLS_ENABLED,
        "offline_mode": config.OFFLINE_MODE,
        "llm_narrative_enabled": config.LLM_NARRATIVE_ENABLED,
        "llm_backend_reachable": ollama_up,
        "findings_db": os.path.exists(config.FINDINGS_DB_PATH),
        "license": {
            "status": config.LICENSE_STATUS,
            "info": config.LICENSE_INFO
        },

    }


@app.get("/api/readyz")
def readyz():
    try:
        get_store()
        return {"ready": True}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"not ready: {e}")


@app.get("/api/rules")
def rules():
    aws_rules = [{"id": p["id"], "name": p["name"], "actions": p["actions"], "provider": p.get("provider", "aws")} for p in ESCALATION_PRIMITIVES]
    azure_rules = [
        {"id": "AZ.WILDCARD_ACTION_ALL", "name": "Role grants ALL control-plane actions (actions: \"*\")", "actions": ["actions: *"], "provider": "azure"},
        {"id": "AZ.WILDCARD_DATAACTION_ALL", "name": "Role grants ALL data-plane actions (dataActions: \"*\")", "actions": ["dataActions: *"], "provider": "azure"},
        {"id": "AZ.NOTACTIONS_TRAP", "name": "actions:* softened only by notActions", "actions": ["notActions"], "provider": "azure"},
        {"id": "AZ.ESC_ROLE_ASSIGNMENT_WRITE", "name": "Grant role assignments to any identity (self-escalation to Owner)", "actions": ["Microsoft.Authorization/roleAssignments/write"], "provider": "azure"},
        {"id": "AZ.ESC_AUTHORIZATION_ALL", "name": "Full access to authorization subsystem", "actions": ["Microsoft.Authorization/*"], "provider": "azure"},
        {"id": "AZ.ESC_ELEVATE_ACCESS", "name": "Elevate to User Access Administrator at root scope", "actions": ["Microsoft.Authorization/elevateAccess/action"], "provider": "azure"},
        {"id": "AZ.ESC_ROLE_DEFINITION_WRITE", "name": "Create or modify custom role definitions to grant more access", "actions": ["Microsoft.Authorization/roleDefinitions/write"], "provider": "azure"},
        {"id": "AZ.ESC_MANAGED_IDENTITY_ASSIGN", "name": "Assign managed identity to compute (identity abuse, PassRole-like)", "actions": ["Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action"], "provider": "azure"},
        {"id": "AZ.ESC_DEPLOYMENTS_WRITE", "name": "Deploy ARM templates that run as a privileged identity", "actions": ["Microsoft.Resources/deployments/write"], "provider": "azure"},
        {"id": "AZ.ESC_AUTOMATION_RUNBOOK", "name": "Create or modify automation runbooks executing as privileged identity", "actions": ["Microsoft.Automation/automationAccounts/runbooks/write"], "provider": "azure"},
        {"id": "AZ.ESC_COMPUTE_RUN_COMMAND", "name": "Execute arbitrary shell commands inside Azure VMs as root/SYSTEM", "actions": ["Microsoft.Compute/virtualMachines/runCommand/action"], "provider": "azure"},
        {"id": "AZ.ESC_LOGIC_APP_TRIGGER", "name": "Trigger Logic Apps executing as managed identities", "actions": ["Microsoft.Logic/workflows/triggers/listCallbackUrl/action"], "provider": "azure"},
        {"id": "AZ.ESC_CONTAINER_EXEC", "name": "Execute shell commands inside container instances as root", "actions": ["Microsoft.ContainerInstance/containerGroups/exec/action"], "provider": "azure"},
        {"id": "AZ.ESC_KEYVAULT_SECRETS", "name": "Read sensitive secrets and passwords stored in KeyVault", "actions": ["Microsoft.KeyVault/vaults/secrets/read"], "provider": "azure"},
        {"id": "AZ.ESC_WEB_APP_CONFIG", "name": "Extract App Service connection strings and application secrets", "actions": ["Microsoft.Web/sites/config/list/action"], "provider": "azure"},
        {"id": "AZ.SCOPE_ROOT", "name": "Role assignable at tenant root scope (\"/\")", "actions": ["assignableScopes: /"], "provider": "azure"},
        {"id": "AZ.SCOPE_SUBSCRIPTION", "name": "Role assignable across an entire subscription", "actions": ["assignableScopes: /subscriptions/*"], "provider": "azure"},
        {"id": "AZ.SCOPE_MANAGEMENT_GROUP", "name": "Role assignable across management group hierarchy", "actions": ["assignableScopes: /providers/Microsoft.Management/managementGroups/*"], "provider": "azure"},
    ]
    gcp_rules = [
        {"id": "GCP.PUBLIC_MEMBER", "name": "Role granted to the public (allUsers / allAuthenticatedUsers)", "actions": ["members: allUsers", "members: allAuthenticatedUsers"], "provider": "gcp"},
        {"id": "GCP.PRIMITIVE_ROLE", "name": "Primitive role in use (roles/owner, roles/editor)", "actions": ["roles/owner", "roles/editor"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_SECURITY_ADMIN", "name": "Manage IAM policy (grant any role) — setIamPolicy", "actions": ["roles/iam.securityAdmin"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_TOKEN_CREATOR", "name": "Mint access tokens for service accounts (impersonation)", "actions": ["roles/iam.serviceAccountTokenCreator"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_SERVICE_USER", "name": "actAs service accounts (run workloads as their identity)", "actions": ["roles/iam.serviceAccountUser"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_KEY_ADMIN", "name": "Create service-account keys (persistent impersonation)", "actions": ["roles/iam.serviceAccountKeyAdmin"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_ROLE_ADMIN", "name": "Create or modify custom roles to grant more access", "actions": ["roles/iam.roleAdmin"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_COMPUTE_ADMIN", "name": "Full control over Compute Engine instances (metadata SSH escalation)", "actions": ["roles/compute.admin"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_FUNCTIONS_DEV", "name": "Deploy Cloud Functions executing as privileged service accounts", "actions": ["roles/cloudfunctions.developer"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_BUILD_EDITOR", "name": "Submit Cloud Builds executing as privileged build service account", "actions": ["roles/cloudbuild.builds.editor"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_WORKFLOW_EDITOR", "name": "Execute Workflows executing as privileged service accounts", "actions": ["roles/workflows.editor"], "provider": "gcp"},
        {"id": "GCP.ESC_ROLE_SECRET_ACCESSOR", "name": "Access secret payloads across Secret Manager", "actions": ["roles/secretmanager.secretAccessor"], "provider": "gcp"},
        {"id": "GCP.ESC_PERMISSION", "name": "Escalation-enabling permission (actAs, getAccessToken, setIamPolicy)", "actions": ["iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken", "resourcemanager.projects.setIamPolicy", "compute.instances.setMetadata"], "provider": "gcp"},
        {"id": "GCP.WILDCARD_PERMISSION", "name": "Wildcard permission in custom role", "actions": ["*"], "provider": "gcp"},
    ]
    all_rules = aws_rules + azure_rules + gcp_rules
    return {
        "ruleset_version": config.RULESET_VERSION,
        "providers": list(PROVIDERS),
        "aws_escalation_primitives": aws_rules,
        "azure_escalation_primitives": azure_rules,
        "gcp_escalation_primitives": gcp_rules,
        "escalation_primitives": all_rules,
    }



@app.get("/api/license")
def license_info(principal: auth.Principal = Depends(require_role("viewer"))):
    return LICENSE.to_public_dict()


@app.get("/api/usage")
def usage(principal: auth.Principal = Depends(require_role("viewer"))):
    return metering.usage_summary(get_store(), LICENSE)


@app.post("/api/audit/iam")
def iam_audit(req: IAMAuditRequest, request: Request,
              principal: auth.Principal = Depends(require_role("analyst"))):
    request_id = getattr(request.state, "request_id", None)
    # Enforce licensed quota/seats BEFORE doing work.
    try:
        metering.enforce_quota(get_store(), LICENSE, principal.actor)
    except metering.QuotaExceeded as e:
        raise HTTPException(status_code=402, detail=str(e))

    if req.provider and req.provider not in ("auto",) + PROVIDERS:
        raise HTTPException(status_code=400, detail=f"provider must be auto|{'|'.join(PROVIDERS)}.")
    try:
        data = json.loads(req.policy_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in policy_json.")
    try:
        result = analyze(data, target=req.target or "pasted policy", provider=req.provider or "auto",
                         model=req.model, backend=req.backend or "ollama", structured=True)
        scan_id = get_store().record_scan(
            result["scan"], actor=principal.actor, request_id=request_id,
            llm_narrative_ok=result.get("llm_narrative_ok", True))
        return {
            "scan_id": scan_id,
            "provider": result.get("provider"),
            "scan": result["scan"],
            "report": result["report"],
            "llm_narrative_ok": result.get("llm_narrative_ok", True),
        }
    except Exception as e:
        log.exception("iam_audit failed request_id=%s", request_id)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
def list_scans(target: Optional[str] = None, limit: int = 50,
               principal: auth.Principal = Depends(require_role("viewer"))):
    return {"scans": get_store().list_scans(domain="iam", target=target, limit=min(limit, 500))}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, principal: auth.Principal = Depends(require_role("viewer"))):
    scan = get_store().get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/scans/diff/iam")
def diff_scans(target: str, principal: auth.Principal = Depends(require_role("viewer"))):
    diff = get_store().diff_latest("iam", target)
    if diff is None:
        raise HTTPException(status_code=404, detail="Need at least two scans of this target to diff.")
    return diff


@app.get("/api/admin/audit-log")
def admin_audit_log(limit: int = 100, principal: auth.Principal = Depends(require_role("admin"))):
    """The security-relevant action log. Admin-only (demonstrates the RBAC tier)."""
    return {"audit_log": get_store().recent_audit(limit=min(limit, 1000))}


if __name__ == "__main__":
    tls = {}
    if config.TLS_ENABLED:
        tls = {"ssl_certfile": config.TLS_CERT_FILE, "ssl_keyfile": config.TLS_KEY_FILE}
        log.info("TLS enabled (cert=%s)", config.TLS_CERT_FILE)
    scheme = "https" if config.TLS_ENABLED else "http"
    log.info("Starting %s on %s://%s:%s", config.PRODUCT_NAME, scheme, config.SERVER_HOST, config.SERVER_PORT)
    uvicorn.run(app, host=config.SERVER_HOST, port=config.SERVER_PORT, **tls)
