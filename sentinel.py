#!/usr/bin/env python3
"""
IAM Sentinel — Easy CLI Wrapper.

Usage:
  python3 sentinel.py scan <policy_file.json> [--target NAME] [--key API_KEY]
  python3 sentinel.py diff <target_name> [--key API_KEY]
  python3 sentinel.py health
  python3 sentinel.py test
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.error

# ANSI Color codes for clean terminal output
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEV_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH": ORANGE + BOLD,
    "MEDIUM": YELLOW + BOLD,
    "LOW": CYAN,
    "INFO": RESET
}

DEFAULT_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:8080")
DEFAULT_KEY = os.getenv("IAM_SENTINEL_API_KEY", "CHANGE_ME_32+_char_random_secret")



def make_req(endpoint, method="GET", data=None, api_key=None, base_url=DEFAULT_URL):
    url = f"{base_url.rstrip('/')}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    payload = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            err_json = json.loads(err_body)
            detail = err_json.get("detail", err_body)
        except Exception:
            detail = err_body
        print(f"{RED}{BOLD}API Error ({e.code}):{RESET} {detail}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"{RED}{BOLD}Connection Error:{RESET} Could not reach IAM Sentinel at {url}.\nReason: {e.reason}")
        print("Make sure the container is running: `docker compose up -d`")
        sys.exit(1)


def cmd_health(args):
    data = make_req("/api/health", base_url=args.url)
    print(f"\n{BOLD}🛡️ IAM Sentinel Status{RESET}")
    print(f"  Status:               {GREEN}Online{RESET}" if data.get("status") == "online" else f"  Status: {RED}Offline{RESET}")
    print(f"  Engine Version:       {data.get('engine_version')}")
    print(f"  Ruleset Version:      {data.get('ruleset_version')}")
    print(f"  Auth Enabled:         {data.get('auth_enabled')}")
    print(f"  Offline Mode:         {data.get('offline_mode')}")
    print(f"  LLM Backend Reachable: {data.get('llm_backend_reachable')}\n")


def cmd_scan(args):
    if not os.path.exists(args.file):
        print(f"{RED}File not found:{RESET} {args.file}")
        sys.exit(1)

    with open(args.file, "r") as f:
        policy_str = f.read()

    try:
        json.loads(policy_str)
    except json.JSONDecodeError as e:
        print(f"{RED}Invalid JSON in {args.file}:{RESET} {e}")
        sys.exit(1)

    print(f"{CYAN}Auditing IAM Policy:{RESET} {args.file} (target: {args.target})...")

    data = make_req("/api/audit/iam", method="POST", data={
        "policy_json": policy_str,
        "target": args.target
    }, api_key=args.key, base_url=args.url)

    scan = data.get("scan", {})
    findings = scan.get("findings", [])
    highest = scan.get("highest_severity", "CLEAN")
    counts = scan.get("severity_counts", {})

    color = SEV_COLORS.get(highest, GREEN + BOLD)

    print(f"\n{BOLD}══════════════════════════════════════════════════════════════════{RESET}")
    print(f" {BOLD}IAM SENTINEL SCAN RESULTS{RESET} (Scan ID: {data.get('scan_id')})")
    print(f" Highest Severity: {color}{highest}{RESET}")
    print(f" Total Findings:   {BOLD}{len(findings)}{RESET} ({counts})")
    print(f" Policy SHA-256:   {scan.get('artifact_sha256')}")
    print(f"{BOLD}══════════════════════════════════════════════════════════════════{RESET}\n")

    if not findings:
        print(f"{GREEN}{BOLD}✅ PASS: No privilege-escalation paths or policy flaws detected.{RESET}\n")
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            scolor = SEV_COLORS.get(sev, RESET)
            print(f" {BOLD}{idx}. [{scolor}{sev}{RESET}{BOLD}] {f.get('rule_id')}{RESET}")
            print(f"    {BOLD}Title:{RESET} {f.get('title')}")
            print(f"    {BOLD}Description:{RESET} {f.get('description')}")
            print(f"    {BOLD}Evidence:{RESET} {f.get('evidence')}")
            print(f"    {BOLD}Fix:{RESET} {GREEN}{f.get('remediation_hint')}{RESET}")
            print()

    if data.get("report") and data.get("llm_narrative_ok"):
        print(f"{BOLD}--- Remediation Narrative ---{RESET}")
        print(data["report"])


def cmd_diff(args):
    data = make_req(f"/api/scans/diff/iam?target={args.target}", api_key=args.key, base_url=args.url)
    print(f"\n{BOLD}🔍 Cross-Run Diff for Target:{RESET} {args.target}")
    fixed = data.get("fixed", [])
    new_f = data.get("new", [])
    persistent = data.get("persistent", [])

    print(f"  {GREEN}Fixed Findings:      {len(fixed)}{RESET}")
    for f in fixed:
        print(f"    - [{f['severity']}] {f['rule_id']}: {f['title']}")

    print(f"  {RED}New Findings:        {len(new_f)}{RESET}")
    for f in new_f:
        print(f"    - [{f['severity']}] {f['rule_id']}: {f['title']}")

    print(f"  {YELLOW}Persistent Findings: {len(persistent)}{RESET}")
    for f in persistent:
        print(f"    - [{f['severity']}] {f['rule_id']}: {f['title']}")
    print()


def cmd_test(args):
    import subprocess
    print(f"{CYAN}Running IAM Sentinel Test Suite...{RESET}")
    res = subprocess.run(["python3", "-m", "unittest", "discover", "-v", "-s", "tests"])
    sys.exit(res.returncode)


def main():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--url", default=DEFAULT_URL, help="IAM Sentinel API base URL")
    parent_parser.add_argument("--key", default=DEFAULT_KEY, help="API Key (X-API-Key header)")

    parser = argparse.ArgumentParser(parents=[parent_parser], description="IAM Sentinel CLI — Simple privilege-escalation auditor.")
    sub = parser.add_subparsers(dest="command", required=True)

    # Health
    p_health = sub.add_parser("health", parents=[parent_parser], help="Check server health & engine readiness")
    p_health.set_defaults(func=cmd_health)

    # Scan
    p_scan = sub.add_parser("scan", parents=[parent_parser], help="Audit an IAM policy JSON file")
    p_scan.add_argument("file", help="Path to IAM policy JSON file")
    p_scan.add_argument("--target", default="default-target", help="Resource / role name target")
    p_scan.set_defaults(func=cmd_scan)

    # Diff
    p_diff = sub.add_parser("diff", parents=[parent_parser], help="Diff the last 2 scans of a target")
    p_diff.add_argument("target", help="Target name to diff")
    p_diff.set_defaults(func=cmd_diff)

    # Test
    p_test = sub.add_parser("test", parents=[parent_parser], help="Run local unit test suite")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
