#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           Cloud Compliance Resource Manager                      ║
║   Manages vulnerable AWS + GCP demo resources for scanner tests  ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python manage_resources.py

Options available from the interactive menu:
    1  Deploy all vulnerable resources    (terraform apply + scan trigger)
    2  Update / patch resources           (re-apply terraform + re-scan)
    3  Trigger scans only                 (no terraform, just API calls)
    4  Show resource status               (terraform state list)
    5  Destroy all demo resources         (terraform destroy)
    6  Exit

Returns text confirmation on each action.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
INFRA_DIR    = SCRIPT_DIR
ENV_FILE     = PROJECT_ROOT / ".env"
BACKEND_URL  = "http://localhost:8000"

# ANSI color codes
R  = "\033[0;31m"   # Red
G  = "\033[0;32m"   # Green
Y  = "\033[0;33m"   # Yellow
B  = "\033[0;34m"   # Blue
C  = "\033[0;36m"   # Cyan
W  = "\033[1;37m"   # Bold white
DIM = "\033[0;90m"  # Dim grey
NC = "\033[0m"      # Reset


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def load_env() -> dict[str, str]:
    """Load .env file into a dict (does not override existing os.environ)."""
    env: dict[str, str] = {}
    if not ENV_FILE.exists():
        return env
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def make_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a subprocess environment with .env + OS env merged."""
    env_vars = load_env()
    merged = {**os.environ, **env_vars}
    if extra:
        merged.update(extra)
    return merged


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""
{C}╔══════════════════════════════════════════════════════════════════╗
║        Cloud Compliance Resource Manager  v1.0                   ║
║   Manages intentionally vulnerable AWS + GCP demo resources       ║
╚══════════════════════════════════════════════════════════════════╝{NC}

{DIM}Infra dir : {INFRA_DIR}
Backend   : {BACKEND_URL}
Env file  : {ENV_FILE}{NC}
""")


def print_menu():
    print(f"""{W}Select an action:{NC}

  {G}[1]{NC} Deploy all vulnerable resources   {DIM}(terraform apply + scan){NC}
  {Y}[2]{NC} Update / patch resources          {DIM}(re-apply changes + re-scan){NC}
  {B}[3]{NC} Trigger scans only                {DIM}(no terraform, API only){NC}
  {C}[4]{NC} Show resource status              {DIM}(terraform state list){NC}
  {R}[5]{NC} Destroy all demo resources        {DIM}(terraform destroy){NC}
  {DIM}[6]{NC} Exit
""")


def confirm(prompt: str) -> bool:
    resp = input(f"{Y}{prompt} [y/N]: {NC}").strip().lower()
    return resp in ("y", "yes")


def print_step(msg: str):
    print(f"\n{C}▶ {msg}{NC}")


def print_ok(msg: str):
    print(f"{G}✅ {msg}{NC}")


def print_warn(msg: str):
    print(f"{Y}⚠  {msg}{NC}")


def print_err(msg: str):
    print(f"{R}✗  {msg}{NC}")


# ─────────────────────────────────────────────────────────────────────────────
# Terraform helpers
# ─────────────────────────────────────────────────────────────────────────────

def run_terraform(args: list[str], stream: bool = True) -> tuple[int, str]:
    """
    Run a terraform command inside INFRA_DIR.
    Streams output to stdout if stream=True.
    Returns (exit_code, combined_output).
    """
    cmd = ["terraform"] + args
    print_step(f"Running: {' '.join(cmd)}")
    env = make_env()

    buf: list[str] = []
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(INFRA_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:  # type: ignore[union-attr]
            if stream:
                print(f"  {DIM}{line.rstrip()}{NC}")
            buf.append(line)
        proc.wait()
        return proc.returncode, "".join(buf)
    except FileNotFoundError:
        print_err("terraform not found in PATH. Install it from https://developer.hashicorp.com/terraform/install")
        return 1, ""


def terraform_init() -> bool:
    """Run terraform init if .terraform dir doesn't exist."""
    tf_dir = INFRA_DIR / ".terraform"
    if not tf_dir.exists():
        print_step("Initialising Terraform (first run)...")
        code, _ = run_terraform(["init", "-input=false"])
        return code == 0
    return True


def terraform_apply(targets: list[str] | None = None) -> tuple[bool, str]:
    """
    Apply Terraform. Optionally restrict to specific -target resources.
    Returns (success, summary_message).
    """
    args = ["apply", "-auto-approve", "-input=false"]
    if targets:
        for t in targets:
            args += ["-target", t]

    code, output = run_terraform(args)
    if code == 0:
        # Parse summary line
        for line in output.splitlines()[::-1]:
            if "Apply complete!" in line or "added" in line:
                return True, line.strip()
        return True, "Apply complete."
    return False, f"Terraform apply failed (exit {code})."


def terraform_plan() -> tuple[bool, str]:
    """Run terraform plan and return (success, summary)."""
    code, output = run_terraform(["plan", "-input=false"])
    for line in output.splitlines()[::-1]:
        if "Plan:" in line or "No changes" in line:
            return code == 0, line.strip()
    return code == 0, "Plan complete."


def terraform_state_list() -> list[str]:
    """Return list of managed resource addresses."""
    code, output = run_terraform(["state", "list"], stream=False)
    if code != 0:
        return []
    return [l.strip() for l in output.splitlines() if l.strip()]


def terraform_destroy(targets: list[str] | None = None) -> tuple[bool, str]:
    """Destroy all (or targeted) managed resources."""
    args = ["destroy", "-auto-approve", "-input=false"]
    if targets:
        for t in targets:
            args += ["-target", t]
    code, output = run_terraform(args)
    for line in output.splitlines()[::-1]:
        if "Destroy complete!" in line or "destroyed" in line:
            return code == 0, line.strip()
    return code == 0, f"Destroy {'complete' if code == 0 else 'failed'}."


# ─────────────────────────────────────────────────────────────────────────────
# Backend API helpers
# ─────────────────────────────────────────────────────────────────────────────

def _api(
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
    timeout: int = 30,
) -> tuple[int, dict]:
    """Low-level HTTP helper. Returns (status_code, json_body)."""
    url = BACKEND_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode()
            return e.code, {"error": body_text}
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


def get_token(env: dict[str, str]) -> str | None:
    """Authenticate with the backend and return a JWT token."""
    # Try reading from env, then prompt
    email    = env.get("ADMIN_EMAIL", "admin@compliance.local")
    password = env.get("ADMIN_PASSWORD", "")

    if not password:
        print(f"\n{Y}Backend login required (user: {email}){NC}")
        import getpass
        password = getpass.getpass("Password: ")

    print_step(f"Authenticating as {email}...")
    status, resp = _api(
        "POST", "/api/v1/auth/login",
        body={"email": email, "password": password},
    )
    if status == 200 and "access_token" in resp:
        print_ok("Authenticated successfully.")
        return resp["access_token"]
    print_warn(f"Auth failed ({status}): {resp.get('error', resp)}")
    return None


def wait_for_backend(timeout: int = 30) -> bool:
    """Poll /api/v1/health until the backend responds."""
    print_step(f"Waiting for backend at {BACKEND_URL}...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BACKEND_URL}/api/v1/health", timeout=3) as r:
                if r.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def get_cloud_accounts(token: str) -> list[dict]:
    """Fetch all active cloud accounts."""
    status, resp = _api("GET", "/api/v1/cloud-accounts", token=token)
    if status == 200:
        return resp if isinstance(resp, list) else resp.get("items", [])
    return []


def trigger_compliance_scan(token: str, account_id: int, framework: str = "all") -> dict:
    """Trigger a compliance scan for a cloud account."""
    status, resp = _api(
        "POST",
        f"/api/v1/compliance/scan",
        body={"account_id": account_id, "framework": framework},
        token=token,
    )
    return {"status": status, "response": resp}


def trigger_dspm_refresh(token: str) -> dict:
    """Trigger a DSPM engine refresh."""
    status, resp = _api("POST", "/api/v1/dspm/refresh", token=token)
    return {"status": status, "response": resp}


def trigger_violations_refresh(token: str) -> dict:
    """Trigger the violations engine."""
    status, resp = _api("POST", "/api/v1/violations/refresh", token=token)
    return {"status": status, "response": resp}


def run_all_scans(token: str) -> str:
    """Trigger scans for all cloud accounts + DSPM + violations. Returns summary."""
    print_step("Fetching cloud accounts...")
    accounts = get_cloud_accounts(token)
    if not accounts:
        print_warn("No cloud accounts found via API. Scan skipped.")
        return "No cloud accounts registered."

    scan_results: list[str] = []

    for acct in accounts:
        acct_id   = acct.get("id")
        acct_name = acct.get("name", str(acct_id))
        provider  = acct.get("provider", "?")
        if not acct_id:
            continue
        print_step(f"Triggering scan: {acct_name} ({provider}) id={acct_id}")
        result = trigger_compliance_scan(token, acct_id)
        http_status = result["status"]
        if http_status in (200, 202):
            scan_id = result["response"].get("scan_id", "?")
            print_ok(f"Scan queued → scan_id={scan_id}")
            scan_results.append(f"{acct_name}({provider}): scan_id={scan_id}")
        else:
            print_warn(f"Scan failed for {acct_name}: {result['response']}")
            scan_results.append(f"{acct_name}({provider}): FAILED")

    # DSPM
    print_step("Triggering DSPM refresh...")
    d = trigger_dspm_refresh(token)
    dspm_ok = d["status"] in (200, 202)
    print_ok("DSPM refresh queued.") if dspm_ok else print_warn(f"DSPM failed: {d['response']}")

    # Violations
    print_step("Triggering violations engine...")
    v = trigger_violations_refresh(token)
    viol_ok = v["status"] in (200, 202)
    print_ok("Violations engine queued.") if viol_ok else print_warn(f"Violations failed: {v['response']}")

    return (
        f"Scans triggered for {len(scan_results)} account(s): {', '.join(scan_results)}. "
        f"DSPM: {'OK' if dspm_ok else 'FAILED'}. "
        f"Violations: {'OK' if viol_ok else 'FAILED'}."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Menu Actions
# ─────────────────────────────────────────────────────────────────────────────

def action_deploy(token: str) -> str:
    """Deploy all vulnerable resources and trigger scans."""
    print(f"\n{W}═══ Deploying All Vulnerable Resources ═══{NC}\n")

    if not terraform_init():
        return "❌ Terraform init failed. Check your terraform installation."

    ok, summary = terraform_apply()
    if not ok:
        return f"❌ Terraform apply failed: {summary}"

    print_ok(f"Terraform: {summary}")
    time.sleep(3)  # brief pause for GCP/AWS API consistency

    scan_summary = run_all_scans(token)
    result = (
        f"✅ Resources deployed.\n"
        f"   Terraform: {summary}\n"
        f"   Scans:     {scan_summary}"
    )
    print(f"\n{G}{result}{NC}\n")
    return result


def action_update(token: str) -> str:
    """Re-apply terraform (patch drift) and re-scan."""
    print(f"\n{W}═══ Updating / Patching Resources ═══{NC}\n")

    print_step("Running terraform plan to check for changes...")
    plan_ok, plan_summary = terraform_plan()
    if not plan_ok:
        return "❌ Terraform plan failed."

    print_ok(f"Plan: {plan_summary}")

    if "No changes" in plan_summary:
        print_ok("Infrastructure is up-to-date. Triggering re-scan only.")
    else:
        ok, apply_summary = terraform_apply()
        if not ok:
            return f"❌ Terraform apply failed: {apply_summary}"
        print_ok(f"Applied: {apply_summary}")

    scan_summary = run_all_scans(token)
    result = (
        f"✅ Resources updated/patched.\n"
        f"   Terraform: {plan_summary}\n"
        f"   Scans:     {scan_summary}"
    )
    print(f"\n{G}{result}{NC}\n")
    return result


def action_scan_only(token: str) -> str:
    """Trigger all scans without touching infrastructure."""
    print(f"\n{W}═══ Triggering Scans (No Terraform) ═══{NC}\n")
    scan_summary = run_all_scans(token)
    result = f"✅ Scans triggered.\n   {scan_summary}"
    print(f"\n{G}{result}{NC}\n")
    return result


def action_status() -> str:
    """Show current terraform-managed resources."""
    print(f"\n{W}═══ Resource Status ═══{NC}\n")
    resources = terraform_state_list()
    if not resources:
        print_warn("No resources found in Terraform state.")
        return "No managed resources."

    # Categorise by provider
    aws_res = [r for r in resources if r.startswith("aws_")]
    gcp_res = [r for r in resources if r.startswith("google_")]
    other   = [r for r in resources if r not in aws_res and r not in gcp_res]

    print(f"\n{Y}AWS Resources ({len(aws_res)}):{NC}")
    for r in aws_res:
        print(f"  {DIM}•{NC} {r}")

    print(f"\n{C}GCP Resources ({len(gcp_res)}):{NC}")
    for r in gcp_res:
        print(f"  {DIM}•{NC} {r}")

    if other:
        print(f"\n{W}Other ({len(other)}):{NC}")
        for r in other:
            print(f"  {DIM}•{NC} {r}")

    summary = (
        f"✅ Resource status: "
        f"AWS={len(aws_res)}, GCP={len(gcp_res)}, Other={len(other)}, "
        f"Total={len(resources)}"
    )
    print(f"\n{G}{summary}{NC}\n")
    return summary


def action_destroy() -> str:
    """Destroy all terraform-managed demo resources."""
    print(f"\n{R}═══ Destroying All Demo Resources ═══{NC}\n")
    print_warn("This will PERMANENTLY DELETE all Terraform-managed cloud resources.")

    if not confirm("Are you sure you want to destroy all demo resources?"):
        print("Destroy cancelled.")
        return "Destroy cancelled by user."

    ok, summary = terraform_destroy()
    result = (
        f"{'✅' if ok else '❌'} Resources destroyed.\n"
        f"   Terraform: {summary}"
    )
    print(f"\n{'G' if ok else 'R'}{result}{NC}\n")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    env = load_env()

    # Check backend health
    if not wait_for_backend(timeout=15):
        print_warn(
            "Backend is not responding at {BACKEND_URL}. "
            "Terraform operations will still work, but scan triggers will fail."
        )

    # Authenticate once upfront
    token: str | None = None
    try:
        token = get_token(env)
    except KeyboardInterrupt:
        print("\nSkipping authentication — scan triggers disabled.")

    last_result: str = ""

    while True:
        print_banner()
        if last_result:
            print(f"{DIM}Last action: {last_result[:120]}{'...' if len(last_result) > 120 else ''}{NC}\n")

        print_menu()

        try:
            choice = input(f"{W}Enter choice [1-6]: {NC}").strip()
        except (KeyboardInterrupt, EOFError):
            choice = "6"

        if choice == "1":
            if not token:
                print_warn("Not authenticated — scans will be skipped.")
            last_result = action_deploy(token or "")

        elif choice == "2":
            if not token:
                print_warn("Not authenticated — scans will be skipped.")
            last_result = action_update(token or "")

        elif choice == "3":
            if not token:
                print_err("Authentication required for scan-only mode.")
            else:
                last_result = action_scan_only(token)

        elif choice == "4":
            last_result = action_status()

        elif choice == "5":
            last_result = action_destroy()

        elif choice == "6":
            print(f"\n{G}Exiting resource manager. Goodbye!{NC}\n")
            sys.exit(0)

        else:
            print_err(f"Invalid choice: '{choice}'. Enter 1-6.")

        input(f"\n{DIM}Press Enter to return to menu...{NC}")


if __name__ == "__main__":
    main()
