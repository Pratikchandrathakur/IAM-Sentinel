# 🛡️ IAM Sentinel — Production User Manual & Administration Guide

Welcome to the official user manual for deploying, configuring, and operating **IAM Sentinel** across Linux, macOS, Windows (WSL2), and cloud production environments.

---

## 📑 Table of Contents
1. [Overview & Security Architecture](#1-overview--security-architecture)
2. [Enterprise Access Control: RBAC Roles, API Keys & SSO/OIDC](#2-enterprise-access-control-rbac-roles-api-keys--ssooidc)
3. [Prerequisites & Cross-OS Environment Setup](#3-prerequisites--cross-os-environment-setup)
4. [Tier 1: Community Tier Setup Guide](#4-tier-1-community-tier-setup-guide)
5. [Tier 2: Team Tier Setup Guide](#5-tier-2-team-tier-setup-guide)
6. [Tier 3: Enterprise Tier Setup Guide](#6-tier-3-enterprise-tier-setup-guide)
7. [DevSecOps CI/CD PR Gate & Terraform Integration](#7-devsecops-cicd-pr-gate--terraform-integration)
8. [IDE MCP Server Setup (Cursor / Claude Code / VS Code)](#8-ide-mcp-server-setup)
9. [Troubleshooting & Verification Commands](#9-troubleshooting--verification-commands)

---

## 1. Overview & Security Architecture

IAM Sentinel is an **air-gapped, zero-telemetry, multi-cloud IAM privilege-escalation auditor and DevSecOps PR gate**.

* **Deterministic Engine**: Powered by 62 ground-truth escalation primitives across AWS, Azure, and GCP. It requires **no machine learning models, no external LLM dependencies, and zero outbound network connections**.
* **Cryptographic Licensing**: Uses Ed25519 public-key signature verification for offline license enforcement.
* **Storage**: Self-contained SQLite database storing audit logs, findings, and remediation diffs.

---

## 2. Enterprise Access Control: RBAC Roles, API Keys & SSO/OIDC

IAM Sentinel enforces an explicit Role-Based Access Control (RBAC) hierarchy.

### 👥 RBAC Role Hierarchy
1. **`viewer`** (Lowest Privilege):
   * Can query `/api/health`, `/api/license`, `/api/rules`, `/api/usage`, and view the Web UI.
   * Cannot run new audits or modify stored data.
2. **`analyst`** (Standard Security Operations):
   * Includes `viewer` rights.
   * Can perform IAM audits (`/api/audit/iam`), query remediation diffs (`/api/scans/diff/iam`), and run CI/CD guardrails.
3. **`admin`** (Full Administrative Control):
   * Full operational authority across all endpoints, export system logs, and configure custom rules.

---

### 🔑 1. API Key Configuration (`IAM_SENTINEL_API_KEYS`)

API keys are configured in your `.env` file using the format:
```text
actor_name:role:secret_key
```

#### Example Configuration in `.env`:
```env
AUTH_ENABLED=true
IAM_SENTINEL_API_KEYS=ci-pipeline:analyst:secret_ci_key_12345,secops-team:analyst:secret_sec_key_67890,ciso-admin:admin:secret_admin_key_99999
```

#### How Callers Authenticate via HTTP Header:
```bash
curl -sk https://127.0.0.1:8443/api/audit/iam \
  -H "X-API-Key: secret_sec_key_67890" \
  -H "Content-Type: application/json" \
  -d '{"policy_json":"..."}'
```

---

### 🔐 2. Enterprise SSO / OIDC (JWT) Integration

Enterprise customers front IAM Sentinel with an Identity Provider (IdP) like **Okta**, **Azure AD / Entra ID**, **Keycloak**, or **PingFederate**.

#### How it works:
1. The IdP issues a signed JWT token containing user identity and group claims.
2. IAM Sentinel verifies the JWT signature **100% offline** (via local public key or secret) and maps IdP groups to RBAC roles.

#### Enterprise `.env` Configuration for SSO:
```env
SSO_ENABLED=true
JWT_ALG=RS256
JWT_PUBLIC_KEY_FILE=/app/certs/idp_public.pem
JWT_ISSUER=https://idp.enterprise.com
JWT_AUDIENCE=iam-sentinel
JWT_ACTOR_CLAIM=sub
JWT_ROLE_CLAIM=groups
JWT_ROLE_MAP=SecOps-Admins:admin,SecOps-Analysts:analyst,Engineering-Viewers:viewer
```

---

## 3. Prerequisites & Cross-OS Environment Setup

IAM Sentinel runs identically on **Linux (Ubuntu/Debian/RHEL)**, **macOS (Intel/Apple Silicon)**, and **Windows (WSL2 / PowerShell)**.

### System Requirements:
* **Docker Engine** (v20.10+) & **Docker Compose** (v2.0+)
* **Python** 3.9+ (for CLI tools & MCP server)
* **curl** and **jq** (for testing)

---

## 4. Tier 1: Community Tier Setup Guide

* **Cost**: $0 / Free
* **Capacity**: 1 Seat, 100 Scans / month
* **Features**: Multi-cloud deterministic auditing (AWS, Azure, GCP), Native IDE MCP server, local Web UI.

### Step 4.1: Generate TLS Certificates
```bash
cd iam-sentinel
python3 gen_self_signed_cert.py --host 127.0.0.1 --out ./certs
```

### Step 4.2: Create `.env` File
```bash
cat << 'EOF' > .env
AUTH_ENABLED=true
IAM_SENTINEL_API_KEYS=analyst:analyst:secret123,admin:admin:adminsecret
TLS_CERT_FILE=./certs/cert.pem
TLS_KEY_FILE=./certs/key.pem
OFFLINE_MODE=true
LLM_NARRATIVE_ENABLED=false
EOF
```

### Step 4.3: Start Server Container
```bash
docker compose up -d --build
```

### Step 4.4: Verify Server & Perform First Audit
```bash
export KEY=secret123
export URL=https://127.0.0.1:8443

# Check Health
curl -sk $URL/api/health | jq

# Audit AWS Policy
curl -sk $URL/api/audit/iam \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"policy_json":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"ec2:RunInstances\"],\"Resource\":\"*\"}]}","target":"aws-demo"}' \
  | jq '{provider, highest_severity:.scan.highest_severity, rules:[.scan.findings[].rule_id]}'
```

---

## 5. Tier 2: Team Tier Setup Guide

* **Cost**: $199 / month
* **Capacity**: 10 Seats, 5,000 Scans / month
* **Features**: All Community features + **Cross-Run Remediation Diff Engine** (`/api/scans/diff/iam`), Audit Trail History, CI/CD Guardrails.

### Step 5.1: Obtain Team License Key
Request a signed Team tier license key from the product owner / vendor (`krisprogrammer1@gmail.com`). You will receive a signed `LICENSE_KEY` token.

### Step 5.2: Activate License in `.env`
Append your `LICENSE_KEY` token to `.env` and restart Docker:
```bash
# Add key to .env
echo 'LICENSE_KEY=eyJwYXlsb2Fk...<your_vendor_license_token>' >> .env

# Restart server
docker compose up -d
```

### Step 5.3: Test Cross-Run Remediation Diff
Scan a vulnerable policy, scan the remediated version, and query the diff:
```bash
# 1. Audit Vulnerable Policy
curl -sk $URL/api/audit/iam -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"policy_json":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"ec2:RunInstances\"],\"Resource\":\"*\"}]}","target":"prod-role"}' > /dev/null

# 2. Audit Scoped Policy (Fixed)
curl -sk $URL/api/audit/iam -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"policy_json":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"ec2:RunInstances\"],\"Resource\":\"arn:aws:iam::123456789012:role/app\"}]}","target":"prod-role"}' > /dev/null

# 3. Query Remediation Diff
curl -sk "$URL/api/scans/diff/iam?target=prod-role" -H "X-API-Key: $KEY" \
  | jq '{fixed:[.fixed[].rule_id], persistent:[.persistent[].rule_id], new:[.new[].rule_id]}'
```

---

## 6. Tier 3: Enterprise Tier Setup Guide

* **Cost**: $4,999 / year
* **Capacity**: **Unlimited Seats & Scans**
* **Features**: All Team features + **OIDC/SSO Integration**, **Ed25519 Tamper-Proof Cryptographic Verification**, Custom JSON Rule Packs, Air-Gapped High Availability.

### Step 6.1: Obtain Enterprise License Key
Request an Enterprise license key from the product owner / vendor (`krisprogrammer1@gmail.com`). You will receive an offline Ed25519-signed `LICENSE_KEY` token.

### Step 6.2: Configure `.env` for Enterprise Mode
```bash
cat << 'EOF' > .env
AUTH_ENABLED=true
IAM_SENTINEL_API_KEYS=prod-sec-key:analyst:secret123,prod-admin-key:admin:adminsecret
TLS_CERT_FILE=./certs/cert.pem
TLS_KEY_FILE=./certs/key.pem
OFFLINE_MODE=true
LLM_NARRATIVE_ENABLED=false
LICENSE_KEY=eyJwYXlsb2Fk...<your_enterprise_license_token>
EOF

docker compose up -d
```

### Step 6.3: Verify Enterprise License & Unlimited Capacity
```bash
curl -sk $URL/api/license -H "X-API-Key: $KEY" | jq '{plan, seats_display, scans_display, signed}'
```

---

## 7. DevSecOps CI/CD PR Gate & Terraform Integration

Block dangerous IAM grants in GitHub Actions or any CI/CD runner before code merges to `main`.

### Step 7.1: Scan Terraform Plan Output (`guardrails.py`)
```bash
# Create a sample Terraform plan
cat << 'EOF' > tfplan.json
{
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_iam_policy.vuln_policy",
          "type": "aws_iam_policy",
          "values": {
            "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"ec2:RunInstances\"],\"Resource\":\"*\"}]}"
          }
        }
      ]
    }
  }
}
EOF

# Run Guardrail CLI (Exits 1 on high severity finding)
python3 guardrails.py --tfplan tfplan.json --fail-on HIGH
```

### Step 7.2: GitHub Actions Workflow Integration (`.github/workflows/iam-sentinel.yml`)
Add this file to your GitHub repository:
```yaml
name: IAM Sentinel Guardrails PR Gate

on:
  pull_request:
    branches: [ main ]

jobs:
  iam-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run IAM Sentinel Guardrails
        uses: Pratikchandrathakur/IAM-Sentinel@v1
        with:
          tfplan-file: 'tfplan.json'
          fail-on: 'HIGH'
          format: 'sarif'
          output-file: 'iam-sentinel.sarif'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'iam-sentinel.sarif'
```

---

## 8. IDE MCP Server Setup (Cursor / Claude Code / VS Code)

IAM Sentinel includes a native stdio JSON-RPC 2.0 MCP server (`mcp_stdio.py`).

### Step 8.1: Configure MCP in Cursor / Claude Code Settings
Add this block to your editor's MCP server configuration file:

```json
{
  "mcpServers": {
    "iam-sentinel": {
      "command": "python3",
      "args": [
        "/path/to/iam-sentinel/mcp_stdio.py"
      ],
      "env": {
        "AUTH_ENABLED": "false",
        "LLM_NARRATIVE_ENABLED": "false"
      }
    }
  }
}
```

---

## 9. Troubleshooting & Verification Commands

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `curl: (60) SSL certificate problem` | Self-signed TLS cert used | Pass `-k` or `--insecure` to curl. |
| `HTTP 401 Unauthorized` | Missing or invalid API key | Pass `-H "X-API-Key: <your_secret>"` matching `.env`. |
| `HTTP 402 Payment Required` | Community monthly quota reached | Upgrade to Team/Enterprise key, or contact owner. |
| `LICENSE ERROR` on startup | Corrupted key or tampered signature | Obtain valid key from vendor and update `.env`. |
