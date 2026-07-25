#!/usr/bin/env python3
"""
IAM Sentinel — CI/CD guardrail CLI tool.

Extracts policies from Terraform plans or raw JSON files, scans them with the
deterministic IAM engine, and exits with non-zero if findings exceed the specified threshold.

Supports SARIF output for GitHub Code Scanning annotations and Markdown table output
for PR comments / GitHub Step Summaries.

Usage:
  python3 guardrails.py --tfplan plan.json --fail-on HIGH
  python3 guardrails.py policies/*.json --fail-on CRITICAL
  python3 guardrails.py --tfplan plan.json --format sarif > iam.sarif
  python3 guardrails.py --tfplan plan.json --format markdown > comment.md

Exit code: 0 = clean (below threshold), 1 = blocking findings, 2 = usage/parse error.
Pure stdlib + the engine. No config, no auth, no network.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from findings import Severity, sha256_hex, utc_now_iso
from providers import analyze_policy
import remediation
import terraform_extract

# Force UTF-8 output so emoji/markdown never crash on Windows consoles or CI runners
# whose default encoding is cp1252/ascii (a real failure mode for GitHub Actions on Windows).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

RANK = {s.value: s.rank for s in Severity}


def _load_policy_file(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"::warning:: could not parse {path}: {e}", file=sys.stderr)
        return None


def _collect(args) -> list[dict]:
    """Return list of {name, provider, address, policy}."""
    items = []
    if args.tfplan:
        if not os.path.exists(args.tfplan):
            print(f"error: tfplan not found: {args.tfplan}", file=sys.stderr)
            sys.exit(2)
        items += terraform_extract.extract_from_file(args.tfplan)
    for pat in args.paths:
        matches = glob.glob(pat) if any(c in pat for c in "*?[") else [pat]
        for p in matches:
            if os.path.isdir(p):
                matches += glob.glob(os.path.join(p, "**", "*.json"), recursive=True)
                continue
            pol = _load_policy_file(p)
            if pol is not None:
                items.append({"name": os.path.basename(p), "provider": args.provider,
                              "address": p, "policy": pol})
    return items


def _scan_all(items, provider_arg):
    """Run each policy through the engine; return (results, worst_rank)."""
    results = []
    worst = -1
    for it in items:
        prov = it["provider"] if it["provider"] != "auto" else provider_arg
        scan, resolved = analyze_policy(it["policy"], provider=prov, target=it["address"])
        scan.ruleset_version = "iam-2026.07"
        scan.artifact_sha256 = sha256_hex(json.dumps(it["policy"], sort_keys=True))
        for f in scan.deduped():
            worst = max(worst, f.severity.rank)
        results.append({"item": it, "provider": resolved, "scan": scan})
    return results, worst


def _print_text(results):
    total = 0
    for r in results:
        scan = r["scan"]; findings = scan.deduped(); total += len(findings)
        tag = scan.highest_severity.value if findings else "CLEAN"
        print(f"\n[{tag}] {r['provider'].upper()} :: {r['item']['address']}  ({len(findings)} finding(s))")
        for f in findings:
            print(f"   - {f.severity.value:8s} {f.rule_id}: {f.title}")
            if f.remediation_hint:
                print(f"       fix: {f.remediation_hint}")
    print(f"\nScanned {len(results)} policy/policies · {total} finding(s) total.")


def _markdown_table(results, fail_on="HIGH", worst=-1) -> str:
    lines = ["### 🛡️ IAM Sentinel Guardrails Audit Report", ""]
    total = 0
    threshold = RANK.get(fail_on, 30)

    rows = []
    for r in results:
        scan = r["scan"]
        findings = scan.deduped()
        total += len(findings)
        addr = r["item"]["address"]
        prov = r["provider"].upper()
        if not findings:
            rows.append(f"| `PASS` | **{prov}** | `{addr}` | — | Clean (no dangerous grants) | — |")
        for f in findings:
            badge = "🚨 CRITICAL" if f.severity.value == "CRITICAL" else ("⚠️ HIGH" if f.severity.value == "HIGH" else f"ℹ️ {f.severity.value}")
            hint = f.remediation_hint or "Restrict permissions"
            rows.append(f"| {badge} | **{prov}** | `{addr}` | `{f.rule_id}` | {f.title} | `{hint}` |")

    blocking = worst >= threshold
    status_msg = "❌ **BUILD FAILED** (findings at or above threshold)" if blocking else "✅ **BUILD PASSED**"
    lines.append(f"**Status:** {status_msg}  ")
    lines.append(f"**Fail-On Threshold:** `{fail_on}` | **Policies Scanned:** `{len(results)}` | **Findings:** `{total}`")
    lines.append("")
    lines.append("| Status | Provider | Policy / Resource | Rule ID | Finding | Remediation Hint |")
    lines.append("|---|---|---|---|---|---|")
    lines.extend(rows)
    lines.append("")
    lines.append("*Generated by [IAM Sentinel](https://github.com/Pratikchandrathakur/IAM-Sentinel) — Deterministic Cloud IAM Auditor.*")
    return "\n".join(lines)


def _sarif(results) -> dict:
    rules, rule_ids, sarif_results = [], set(), []
    lvl = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    for r in results:
        for f in r["scan"].deduped():
            if f.rule_id not in rule_ids:
                rule_ids.add(f.rule_id)
                rules.append({"id": f.rule_id, "name": f.rule_id,
                              "shortDescription": {"text": f.title},
                              "helpUri": (f.references[0] if f.references else "")})
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": lvl.get(f.severity.value, "warning"),
                "message": {"text": f"[{f.severity.value}] {f.title} — {f.remediation_hint}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": r["item"]["address"]},
                    "region": {"startLine": 1}}}],
                "properties": {"provider": r["provider"], "resource": r["item"]["address"]},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "IAM Sentinel", "version": "1.0.0",
                                      "informationUri": "https://github.com/Pratikchandrathakur/IAM-Sentinel",
                                      "rules": rules}},
                  "results": sarif_results}],
    }


def main():
    ap = argparse.ArgumentParser(description="IAM Sentinel CI guardrails — fail the build on IAM privilege escalation.")
    ap.add_argument("paths", nargs="*", help="Policy JSON files, globs, or directories")
    ap.add_argument("--tfplan", help="terraform show -json output to extract IAM from")
    ap.add_argument("--provider", default="auto", choices=["auto", "aws", "azure", "gcp"])
    ap.add_argument("--fail-on", default="HIGH", choices=list(RANK), help="Min severity that fails the build")
    ap.add_argument("--format", default="text", choices=["text", "json", "sarif", "markdown"])
    ap.add_argument("--comment-file", help="Write markdown PR comment summary to this file")
    args = ap.parse_args()

    if not args.paths and not args.tfplan:
        ap.error("provide policy files/dirs and/or --tfplan")

    items = _collect(args)
    if not items:
        print("No IAM policies found to scan.", file=sys.stderr)
        # Nothing to scan is not a failure — a PR may not touch IAM.
        if args.format == "sarif":
            print(json.dumps(_sarif([])))
        elif args.format == "markdown":
            print("### 🛡️ IAM Sentinel Guardrails Audit Report\n\nNo IAM policies modified in this PR.")
        sys.exit(0)

    results, worst = _scan_all(items, args.provider)
    threshold = RANK[args.fail_on]

    md_content = _markdown_table(results, fail_on=args.fail_on, worst=worst)

    if args.comment_file:
        with open(args.comment_file, "w", encoding="utf-8") as f:
            f.write(md_content)

    # Write to GitHub Step Summary if environment variable exists
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as f:
                f.write("\n" + md_content + "\n")
        except Exception as e:
            print(f"::warning:: could not write to GITHUB_STEP_SUMMARY: {e}", file=sys.stderr)

    if args.format == "sarif":
        print(json.dumps(_sarif(results), indent=2))
    elif args.format == "json":
        print(json.dumps([{"address": r["item"]["address"], "provider": r["provider"],
                           **r["scan"].to_dict()} for r in results], indent=2))
    elif args.format == "markdown":
        print(md_content)
    else:
        _print_text(results)

    blocking = worst >= threshold
    if args.format == "text":
        if blocking:
            print(f"\n[FAIL] findings at or above '{args.fail_on}'. Blocking the pipeline.")
        else:
            print(f"\n[PASS] no findings at or above '{args.fail_on}'.")
    sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
