<!-- Rename this file to README.md in your public GitHub repo.
     Replace YOUR-USERNAME and the landing-page URL before pushing. -->

<h1 align="center">🛡️ IAM Sentinel</h1>

<p align="center">
  <b>Air-gapped, deterministic cloud IAM privilege-escalation scanner — AWS · Azure · GCP.</b><br>
  Runs 100% on your own metal. Plugs into Cursor / Claude Code via MCP. Zero data egress.
</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue">
  <img alt="docker" src="https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white">
  <img alt="clouds" src="https://img.shields.io/badge/clouds-AWS%20%7C%20Azure%20%7C%20GCP-orange">
  <img alt="offline" src="https://img.shields.io/badge/network-air--gapped-10b981">
  <img alt="tests" src="https://img.shields.io/badge/tests-57%20passing-brightgreen">
</p>

<p align="center">
  <a href="https://iam-sentinel.vercel.app">Website</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="INSTALL.md">Install (Mac/Win/Linux/WSL)</a> ·
  <a href="#pricing">Pricing</a>
</p>

---

## Why

Cloud IAM scanners (Wiz, Snyk, GitHub Advanced Security) send your policies to *their* cloud.
Regulated teams **can't** do that. IAM Sentinel finds privilege-escalation paths, wildcards,
`PassRole`/`roleAssignment` abuse, public bindings, and data-exfil grants with a **deterministic
rule engine** — reproducible and auditable, not an LLM guess — entirely on your infrastructure.

- 🔒 **Air-gapped** — no telemetry, no outbound calls (except an *optional* local model).
- 🎯 **Deterministic** — version-stamped findings from a rule engine, not hallucinations.
- 🔌 **In your IDE** — native stdio MCP server for Cursor / Claude Code.
- 🧾 **Auditable** — every scan persisted with actor, timestamp, SHA-256, and rule-pack version.
- 🖥️ **Runs anywhere** — CPU-only core; a GPU is only for the optional written remediation.

## Quickstart

```bash
git clone https://github.com/YOUR-USERNAME/iam-sentinel && cd iam-sentinel
cp .env.example .env          # set API keys (Community tier needs no license)
docker compose up -d --build
open http://127.0.0.1:8080     # dashboard · API at /api/... · health at /api/health
```

Audit a policy (provider auto-detected):
```bash
curl -s http://127.0.0.1:8080/api/audit/iam -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"policy_json":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}' | jq
```

No GPU / macOS? Set `LLM_NARRATIVE_ENABLED=false` — you still get every deterministic finding.
Full per-OS steps in **[INSTALL.md](INSTALL.md)**.

## Use it inside your IDE (MCP)

```json
{ "mcpServers": { "iam-sentinel": {
    "command": "python3", "args": ["/abs/path/to/iam-sentinel/mcp_stdio.py"],
    "env": { "AUTH_ENABLED": "false", "LLM_NARRATIVE_ENABLED": "false" }
}}}
```
Then ask your assistant: *"Audit this IAM policy with iam-sentinel."*

## What it detects

- **AWS** — 19 escalation techniques (Rhino/PMapper): `AttachUserPolicy`, `PutRolePolicy`,
  `CreateAccessKey`, `PassRole`+compute, `UpdateAssumeRolePolicy`, …; wildcards, `NotAction` traps,
  wildcard principals, unconditioned `AssumeRole`, data-exfil grants.
- **Azure** — `roleAssignments/write`, `elevateAccess`, `Microsoft.Authorization/*`, wildcard actions, scope breadth.
- **GCP** — primitive roles, `allUsers` bindings, `setIamPolicy` / `serviceAccountTokenCreator` / `actAs`.

## Pricing

Open-core. Run it free; upgrade for seats, history, and enterprise controls (offline-licensed).

| Tier | Price | Seats | Scans/mo | Adds |
|---|---|---|---|---|
| Community | **Free** | 1 | 100 | AWS/Azure/GCP · MCP · audit trail |
| Team | $199/mo | 10 | 5,000 | Remediation diff |
| Enterprise | $4,999/yr | ∞ | ∞ | SSO/RBAC · TLS · SLA |

See the [website](https://iam-sentinel.vercel.app) or email **you@example.com** for a pilot.

## Tests

```bash
python3 tests/test_iam_engine.py    # + test_multicloud / test_store / test_mcp / test_auth / ...
```

## License

Apache-2.0 (or your choice). See `LICENSE`.

<p align="center"><i>⭐ If this is useful, star the repo — it helps a lot.</i></p>
