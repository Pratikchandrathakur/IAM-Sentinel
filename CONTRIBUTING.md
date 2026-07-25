# Contributing to IAM Sentinel

Thanks for your interest in improving IAM Sentinel! Bug reports, new escalation rules, and
provider coverage are especially welcome.

## Ground rules

- **Findings are deterministic.** New detections must come from the rule engine, not an LLM.
  Every rule needs a fixture test that (a) fires on a vulnerable policy and (b) stays quiet on
  a clean one. No false positives, no false negatives you can avoid.
- **Keep the core dependency-light.** The engines, store, MCP server, and CI guardrails are
  pure standard library. Don't add heavy dependencies to that path.
- **Everything ships offline.** No feature may require an outbound network call (the optional
  local LLM is the only exception, and it must degrade gracefully when absent).

## Dev setup

```bash
git clone https://github.com/Pratikchandrathakur/IAM-Sentinel && cd IAM-Sentinel
pip install -r requirements.txt        # or just run the tests — the core is stdlib
```

## Run the tests (69 tests)

```bash
export AUTH_ENABLED=false LLM_NARRATIVE_ENABLED=false
for t in tests/test_*.py; do python "$t"; done    # each prints "OK"
```
All tests must pass before you open a PR. The GitHub Actions `tests` workflow runs them on every PR.

## Adding a detection rule

- **Quick / custom rules:** add an entry to a `custom_rules.json` (see `custom_rules.example.json`) —
  no code change needed. Good for org-specific escalation chains.
- **Built-in rules:** add to `ESCALATION_PRIMITIVES` in `iam_engine.py` (AWS),
  `iam_engine_azure.py`, or `iam_engine_gcp.py`, and add fixtures to the matching test file.

## Pull requests

1. Fork, branch from `main`.
2. Make the change + tests; run the full suite.
3. Open a PR describing the behavior change and linking any issue.
4. Keep PRs focused and small where possible.

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see [`SECURITY.md`](SECURITY.md).

## Licensing of contributions

IAM Sentinel is distributed under the **Business Source License 1.1** (see [`LICENSE`](LICENSE)).
By submitting a contribution, you agree that your contribution is licensed to the project and
its users under the same terms (inbound = outbound), and that the maintainer may relicense it
consistent with the Change License (Apache-2.0) at the Change Date.
