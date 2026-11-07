#!/usr/bin/env python3
"""L2 heal loop — GitHub side (ADR 0052): triage a FAILED workflow run.

Called by .github/workflows/autoheal.yml on `workflow_run: completed` (failure). It:

  1. downloads the logs of every failed job of that run (gh api),
  2. maps each job to its gate (job name `gN · …`, or the workflow: build-heqk → g2),
  3. classifies each with tools/ci/heal/classify.py (deterministic, no model),
  4. opens ONE issue per failure signature (deduped; a recurrence adds a comment with the run
     link instead of a new issue) and counts prior autofix attempts from that issue,
  5. emits the decision for the next jobs as GITHUB_OUTPUT: action / gate / signature /
     attempts / issue / is_default_branch.

SECURITY: workflow_run executes with repository secrets, so this script — and everything the
autoheal workflow runs — comes from the DEFAULT branch. Logs of the failing run are treated as
untrusted DATA (regex-classified, quoted into issues), never executed.

    triage_run.py --repo owner/name --run-id N [--dry-run] [--logs-dir DIR]
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import classify  # noqa: E402

WORKFLOW_GATE = {"build-heqk": "g2", "secrets-scan": "secrets", "metal": "g6"}
ATTEMPT_MARK = "<!-- autofix-attempt -->"
SEVERITY = ["secret_leak", "vulnerable_dependency", "supply_chain_policy", "ci_wiring", "phase_downgrade", "shell_lint",
            "build_error", "qemu_phase_regression", "e2e_failure", "test_failure", "clippy_regression",
            "toolchain_env", "qemu_budget", "infra_transient", "unknown"]


def gate_for(workflow: str, job_name: str) -> str:
    """Pure: map a job to its gate."""
    m = re.match(r"\s*(g\d+r?)\b", job_name or "")
    if m:
        return m.group(1)
    if "autofix guard" in (job_name or ""):
        return "autofix-guard"
    return WORKFLOW_GATE.get(workflow, "?")


def pick(decisions: list) -> dict:
    """Pure: the most severe decision drives the follow-up job (one heal at a time)."""
    return sorted(decisions, key=lambda d: SEVERITY.index(d["category"]) if d["category"] in SEVERITY else 99)[0]


def issue_title(d: dict) -> str:
    return f"[ci-autoheal] {d['gate']} {d['category']} ({d['signature']})"


def sanitize(line: str) -> str:
    """Pure: log text is untrusted — it must not break out of the fence or @-mention anyone."""
    return line.replace("~~~", "~ ~ ~").replace("```", "` ` `").replace("@", "(at)")


def issue_body(d: dict, run_url: str, run: dict) -> str:
    ev = "\n".join(sanitize(e) for e in d["evidence"][:12])
    return (f"**{d['category']}** in gate `{d['gate']}` (job: {sanitize(str(d.get('job')))}) → action "
            f"**{d['action']}**\n\n- run: {run_url}\n- branch: `{sanitize(str(run.get('head_branch')))}` at "
            f"`{run.get('head_sha', '')[:12]}`\n- ids: {', '.join(d['ids']) or '-'}\n\n~~~~text\n{ev}\n~~~~\n")


def autofix_eligible(run: dict, default_branch: str, repo: str, compare=None) -> bool:
    """Autofix only for a failure of code that IS on the default branch (security-auditor M2):
    a push/schedule run whose head_sha is reachable from the default branch tip. A branch name
    alone is not proof (a tag can be called `main`); workflow_dispatch can target any ref."""
    if run.get("event") not in ("push", "schedule") or run.get("head_branch") != default_branch:
        return False
    sha = run.get("head_sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False
    if compare is None:
        def compare(s):
            return json.loads(gh("api", f"repos/{repo}/compare/{s}...{default_branch}", "-q", "{status}"))["status"]
    try:
        return compare(sha) in ("identical", "ahead")   # default branch == or is ahead of head_sha
    except Exception:
        return False   # fail-closed


def gh(*args, input_text=None):
    p = subprocess.run(["gh", *args], capture_output=True, text=True, input=input_text)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])}: {p.stderr.strip()[:400]}")
    return p.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--logs-dir", default="out/ci/triage")
    ap.add_argument("--dry-run", action="store_true", help="classify only; no issues")
    a = ap.parse_args()
    os.makedirs(a.logs_dir, exist_ok=True)

    run = json.loads(gh("api", f"repos/{a.repo}/actions/runs/{a.run_id}"))
    workflow = run.get("name", "?")
    default_branch = run.get("repository", {}).get("default_branch", "main")
    jobs = json.loads(gh("api", "--paginate", f"repos/{a.repo}/actions/runs/{a.run_id}/jobs?per_page=100",
                         "-q", "[.jobs[] | select(.conclusion==\"failure\") | {id, name}]") or "[]")
    decisions = []
    for j in jobs:
        lp = os.path.join(a.logs_dir, f"{j['id']}.log")
        try:
            text = gh("api", f"repos/{a.repo}/actions/jobs/{j['id']}/logs")
        except RuntimeError as e:
            text = f"(log unavailable: {e})"
        with open(lp, "w") as f:
            f.write(text)
        d = classify.classify_text(text, gate_for(workflow, j["name"]))
        d.update(job=j["name"], job_id=j["id"])
        decisions.append(d)
    if not decisions:
        print("no failed jobs found (cancelled run?) — nothing to triage")
        return 0
    with open(os.path.join(a.logs_dir, "decisions.json"), "w") as f:
        json.dump(decisions, f, indent=2)
    top = pick(decisions)
    run_url = run.get("html_url", "")
    is_default = autofix_eligible(run, default_branch, a.repo)
    issue, attempts = "", 0
    if not a.dry_run:
        gh("label", "create", "ci-autoheal", "--repo", a.repo, "--color", "B60205", "--force",
           "--description", "Opened by the ADR 0052 heal loop")
        for d in decisions:
            title = issue_title(d)
            # ALL states: closing the issue must not reset the attempt budget (security-auditor L2).
            hist = json.loads(gh("issue", "list", "--repo", a.repo, "--state", "all", "--label", "ci-autoheal",
                                 "--search", d["signature"], "--json", "number,title,state,comments"))
            found = [i for i in hist if i.get("state", "").upper() == "OPEN"]
            body = issue_body(d, run_url, run)
            n_att = sum(1 for i in hist for c in i.get("comments", []) if ATTEMPT_MARK in (c.get("body") or ""))
            if found:
                num = found[0]["number"]
                gh("issue", "comment", str(num), "--repo", a.repo, "--body", "Recurred.\n\n" + body)
            else:
                url = gh("issue", "create", "--repo", a.repo, "--title", title, "--label", "ci-autoheal",
                         "--body", body + "\n_Deterministic triage by tools/ci/heal/triage_run.py (ADR 0052)._").strip()
                num = url.rsplit("/", 1)[-1]
            if d is top:
                issue, attempts = str(num), n_att
    out = {"action": top["action"], "gate": top["gate"], "category": top["category"],
           "signature": top["signature"], "attempts": str(attempts), "issue": issue,
           "is_default_branch": "true" if is_default else "false", "run_attempt": str(run.get("run_attempt", 1))}
    for d in decisions:
        print(f"[{d['gate']}] {d.get('job')}: {d['category']} -> {d['action']} ({d['signature']})")
    print("decision:", json.dumps(out))
    gho = os.environ.get("GITHUB_OUTPUT")
    if gho:
        with open(gho, "a") as f:
            for k, v in out.items():
                f.write(f"{k}={v}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
