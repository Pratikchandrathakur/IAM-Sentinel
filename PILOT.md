# IAM Sentinel — 30-Day Design-Partner Pilot Packet

A ready-to-run pilot for a cloud-security / platform team. Goal: prove IAM Sentinel finds
real privilege-escalation risk in your AWS/Azure/GCP policies, on your own infrastructure,
with an auditable trail — in under 30 days.

---

## What you get

- The full product (deterministic AWS + Azure + GCP IAM auditing).
- Native **MCP server** for Claude Code / Cursor (in-IDE checks).
- API-key or **SSO (OIDC)** auth with **RBAC** (viewer / analyst / admin).
- Built-in **TLS** option, audit trail, and remediation diffing.
- An **Enterprise pilot license** (unlimited seats/scans) valid for the pilot window.

## Success criteria (agree these up front)

| # | Criterion | How we measure |
|---|---|---|
| 1 | Finds real risk | ≥ 1 CRITICAL/HIGH escalation path in your existing prod policies |
| 2 | Low noise | Clean, least-privilege policies scan with **zero** findings |
| 3 | Reproducible | Same policy → identical findings + `artifact_sha256` across runs |
| 4 | In the dev loop | An engineer audits a policy from inside their IDE via MCP |
| 5 | Auditable | Every scan appears in `/api/scans` with actor + provenance |
| 6 | Multi-cloud | At least two of AWS / Azure / GCP validated on your real policies |

## Day-by-day

- **Day 0–1 — Deploy.** `docker compose up -d --build`; set API keys (or wire SSO); confirm `/api/health`.
- **Day 2–5 — Baseline.** Bulk-audit a sample of current prod IAM policies; review findings with the team.
- **Day 6–10 — IDE integration.** Register the MCP server in Cursor/Claude Code; audit policies while editing IaC.
- **Day 11–20 — Remediate + prove.** Fix flagged policies; re-scan; use `/api/scans/diff/iam` to show fixed vs. persistent.
- **Day 21–30 — Decide.** Review the audit trail and success criteria; scope a paid plan (Team/Enterprise) + seats.

## Setup (10 minutes)

```bash
cp .env.example .env          # set IAM_SENTINEL_API_KEYS (and LICENSE_KEY if provided)
docker compose up -d --build
curl -s http://127.0.0.1:8080/api/health | jq        # attestation
curl -s http://127.0.0.1:8080/pricing                 # one-pager / pricing
```

Audit a real policy (auto-detects provider):
```bash
curl -s http://127.0.0.1:8080/api/audit/iam -H "X-API-Key: <analyst-key>" \
  -H "Content-Type: application/json" \
  -d @your-policy-request.json | jq '.provider, .scan.highest_severity, .scan.findings[].rule_id'
```

Enable SSO (optional, Enterprise): set `SSO_ENABLED=true`, `JWT_*`, and map your IdP groups to roles.
Enable TLS (optional): `python gen_self_signed_cert.py --host iam-sentinel.internal` then set `TLS_CERT_FILE`/`TLS_KEY_FILE`.

## Commercials (example)

| Plan | Price | Seats | Scans/mo |
|---|---|---|---|
| Community | Free | 1 | 100 |
| Team | $299/mo | 10 | 5,000 |
| Enterprise | Custom | Unlimited | Unlimited (SSO/RBAC/TLS, SLA) |

Pilots convert to an annual Team or Enterprise agreement. Pricing is an example — set your own.

## Data handling (say this to security review)

- Runs entirely on your hardware; **no outbound calls** except to your local LLM backend (optional).
- The audit DB (`/app/data`) holds scan metadata + findings only; back it up with the `sentinel_data` volume.
- License verification is **offline** (Ed25519 signature); no license server, no telemetry.

## Support during pilot

- A shared channel + a named contact.
- Response target: 1 business day (Enterprise pilots: same-day).
