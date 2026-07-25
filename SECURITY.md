# Security Policy

IAM Sentinel is a security tool, so we hold ourselves to a high bar. Thank you for helping
keep it and its users safe.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ security fixes |
| < 1.0   | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately to **krisprogrammer1@gmail.com** with:

- A description of the issue and its impact
- Steps to reproduce (a minimal proof-of-concept if possible)
- Affected version / commit
- Any suggested remediation

You can also use GitHub's **[Private vulnerability reporting](../../security/advisories/new)**
(Security tab → Report a vulnerability).

### What to expect

- **Acknowledgement:** within 3 business days.
- **Assessment & triage:** within 7 business days, with a severity rating.
- **Fix & disclosure:** coordinated. We aim to release a fix before public disclosure and
  will credit you (unless you prefer to remain anonymous).

## Scope

In scope:
- The deterministic engines, API, MCP server, CI guardrails, licensing/auth, and TLS handling.
- Anything that could cause a **false "clean" result** (a missed privilege-escalation path is
  a security bug here), license bypass, auth/RBAC bypass, or SSRF/injection via scanned input.

Out of scope:
- Findings produced *about* a policy you submitted (that's the product working as intended).
- The optional LLM narrative's wording (it is advisory; the deterministic findings are authoritative).
- Issues that require a already-compromised host or physical access.

## Handling of your data

IAM Sentinel runs on your own infrastructure and makes no outbound calls except to your
configured local model backend (optional). Do not send us real production IAM policies when
reporting — a minimal synthetic reproduction is sufficient and safer.
