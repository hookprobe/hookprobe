#!/usr/bin/env python3
"""L2 heal loop driver (ADR 0048): gates → classify → rerun | autofix-in-isolation | escalate.

    tools/ci/heal/heal.py                         run the PR gate set, heal what's red
    tools/ci/heal/heal.py --gates "g1 g4"         specific gates
    tools/ci/heal/heal.py --results out/ci/gate-results.json   heal an existing run
    tools/ci/heal/heal.py --agent claude          Claude Code headless (default if `claude` exists)
    tools/ci/heal/heal.py --agent 'cmd:<shell>'   any agent command (env HEAL_PROMPT_FILE etc.)
    tools/ci/heal/heal.py --agent none            classify + render the prompt only (dry run)
    tools/ci/heal/heal.py --push                  push the autofix/* branch + open a DRAFT PR

Governance (ADR 0011 C9 / CLAUDE.md tiers): the agent works in its OWN git worktree on an
`autofix/*` branch and never touches the operator's checkout. A fix is only *proposed* when
(1) the deterministic autofix guard passes AND (2) the originally-red gate re-runs green in that
worktree. Merging is always a human (Red tier). Every failure signature has an attempt budget
so the loop cannot thrash; everything is reported to out/ci/heal/report.{json,md} and fed to the
Cortex lifecycle log.
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import classify  # noqa: E402  (sibling module)
import autofix_guard  # noqa: E402

GATE_DESC = {"g0": "hygiene + CI wiring", "g1": "static + unit", "g2": "QEMU boot gate",
             "g3": "Mission Control e2e", "g4": "supply chain", "g4r": "reproducibility", "g6": "metal"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def sh(cmd, cwd=ROOT, env=None, timeout=None, check=False):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd} failed: {p.stderr[-800:]}")
    return p


def run_gates(gates, cwd, ci_out):
    env = dict(os.environ, CI_OUT=ci_out)
    p = subprocess.run(["tools/ci/gates.sh", *gates.split()], cwd=cwd, env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, os.path.join(ci_out, "gate-results.json"), p.stdout


def render_prompt(decision, log_text):
    with open(os.path.join(HERE, "prompt.md")) as f:
        t = f.read()
    prot = ", ".join(autofix_guard.load_protected())
    tail = "\n".join(log_text.splitlines()[-80:])
    rep = {"GATE": decision["gate"], "GATE_DESC": GATE_DESC.get(decision["gate"], "?"),
           "CATEGORY": decision["category"], "SIGNATURE": decision["signature"],
           "IDS": ", ".join(decision["ids"]) or "-", "EVIDENCE": "\n".join(decision["evidence"]),
           "LOG_TAIL": tail, "PROTECTED": prot, "MAX_LINES": str(autofix_guard.MAX_LINES),
           "MAX_FILES": str(autofix_guard.MAX_FILES)}
    for k, v in rep.items():
        t = t.replace("{{" + k + "}}", v)
    return t


def invoke_agent(agent, wt, prompt_file, decision_file, timeout):
    env = dict(os.environ, HEAL_PROMPT_FILE=prompt_file, HEAL_DECISION_FILE=decision_file, HEAL_WORKTREE=wt)
    if agent == "claude":
        with open(prompt_file) as f:
            prompt = f.read()
        # Hard spend cap per attempt (the attempt budget caps the count; this caps the cost).
        cmd = ["claude", "-p", prompt, "--permission-mode", "acceptEdits",
               "--max-budget-usd", os.environ.get("HEAL_MAX_BUDGET_USD", "5"),
               "--allowedTools", "Read,Edit,Write,Grep,Glob,Bash(cargo:*),Bash(python3:*),"
               "Bash(tools/ci/gates.sh:*),Bash(./validate.sh),Bash(git diff:*),Bash(git status),Bash(rg:*),Bash(grep:*)"]
    elif agent.startswith("cmd:"):
        cmd = ["bash", "-c", agent[4:]]
    else:
        raise ValueError(agent)
    p = subprocess.run(cmd, cwd=wt, env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "")[-4000:] + (p.stderr or "")[-2000:]


def autofix(decision, log_text, args, state, outdir):
    sig = decision["signature"]
    st = state.setdefault(sig, {"attempts": 0, "history": []})
    if st["attempts"] >= args.max_attempts:
        return {"status": "budget_exhausted", "detail": f"{st['attempts']} attempt(s) already — escalate to a human"}
    st["attempts"] += 1
    n = st["attempts"]
    prompt = render_prompt(decision, log_text)
    pf = os.path.join(outdir, f"{sig}.prompt.md")
    df = os.path.join(outdir, f"{sig}.decision.json")
    with open(pf, "w") as f:
        f.write(prompt)
    with open(df, "w") as f:
        json.dump(decision, f, indent=2)
    if args.agent == "none":
        return {"status": "dry_run", "detail": f"prompt rendered: {pf}"}

    base = sh(["git", "rev-parse", args.base], check=True).stdout.strip()
    branch = f"autofix/{sig}-a{n}"
    wt = os.path.join(outdir, "wt", f"{sig}-a{n}")
    if os.path.exists(wt):
        sh(["git", "worktree", "remove", "--force", wt])
    sh(["git", "branch", "-D", branch])
    sh(["git", "worktree", "add", "-q", "-b", branch, wt, base], check=True)
    rc, agent_out = invoke_agent(args.agent, wt, pf, df, args.agent_timeout)
    with open(os.path.join(outdir, f"{sig}-a{n}.agent.log"), "w") as f:
        f.write(agent_out)

    res = {"branch": branch, "worktree": wt, "base": base, "agent_rc": rc}
    blocked = os.path.join(wt, "AUTOFIX-BLOCKED.md")
    notes_p = os.path.join(wt, "AUTOFIX-NOTES.md")
    notes = open(notes_p).read().strip() if os.path.exists(notes_p) else "(agent left no notes)"
    for p in (notes_p,):
        if os.path.exists(p):
            os.remove(p)
    if os.path.exists(blocked):
        res.update(status="blocked_needs_human", detail=open(blocked).read().strip()[:2000])
        return res
    sh(["git", "add", "-A"], cwd=wt, check=True)
    if sh(["git", "diff", "--cached", "--quiet"], cwd=wt).returncode == 0:
        res.update(status="no_change", detail="agent made no change")
        return res
    msg = f"autofix({decision['category']}): heal {decision['gate']} [{sig}]\n\n{notes}\n\nGenerated-by: tools/ci/heal (ADR 0048)"
    sh(["git", "-c", "user.name=hookprobe-autofix", "-c", "user.email=autofix@hookprobe.invalid",
        "commit", "-q", "-m", msg], cwd=wt, check=True)
    # The guard and its policy come from the TRUSTED tree running this loop (HERE), never from the
    # worktree the agent just edited — otherwise an agent could rewrite the guard to pass itself.
    g = sh([sys.executable, "-I", os.path.join(HERE, "autofix_guard.py"), "--base", base,
            "--head", "HEAD", "--branch", branch, "--require-branch",
            "--protected", os.path.join(HERE, "protected-paths.txt")], cwd=wt)
    res["guard"] = g.stdout.strip()
    if g.returncode != 0:
        res.update(status="rejected_by_guard", detail=g.stdout.strip()[-1500:])
        return res
    grc, _, gout = run_gates(decision["gate"], wt, os.path.join(wt, "out", "ci"))
    res["regate_tail"] = "\n".join(gout.splitlines()[-15:])
    if grc != 0:
        res.update(status="fix_did_not_turn_gate_green", detail=res["regate_tail"])
        return res
    res.update(status="proposed", detail=notes)
    if args.push:
        pr = sh(["git", "push", "-q", "-u", "origin", branch], cwd=wt)
        res["pushed"] = pr.returncode == 0
        if pr.returncode == 0 and shutil.which("gh"):
            body = f"**Autofix proposal (ADR 0048 L2)** — DRAFT, needs human review.\n\n{notes}\n\n" \
                   f"- signature: `{sig}`\n- guard: PASS\n- gate `{decision['gate']}` re-ran green in isolation\n"
            p = sh(["gh", "pr", "create", "--draft", "--base", args.pr_base, "--head", branch,
                    "--title", f"autofix({decision['category']}): heal {decision['gate']}", "--body", body,
                    "--label", "autofix"], cwd=wt)
            res["pr"] = (p.stdout or p.stderr).strip()
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gates", default="pr")
    ap.add_argument("--results")
    ap.add_argument("--agent", default="claude" if shutil.which("claude") else "none")
    ap.add_argument("--max-attempts", type=int, default=2)
    ap.add_argument("--agent-timeout", type=int, default=3600)
    ap.add_argument("--base", default="HEAD")
    ap.add_argument("--pr-base", default="main")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--out", default=os.path.join(os.environ.get("CI_OUT", os.path.join(ROOT, "out", "ci")), "heal"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    state_p = os.path.join(a.out, "state.json")
    state = json.load(open(state_p)) if os.path.exists(state_p) else {}

    if a.results:
        results = a.results
    else:
        print(f"[heal] running gates: {a.gates}")
        rc, results, _ = run_gates(a.gates, ROOT, os.path.dirname(a.out))
        if rc == 0:
            print("[heal] all gates green — nothing to heal")
            return 0
    decisions = classify.classify_results(results)
    doc = json.load(open(results))
    logs = {g["gate"]: g.get("log", "") for g in doc.get("gates", [])}
    report = []
    for d in decisions:
        log_text = open(logs.get(d["gate"], ""), errors="replace").read() if os.path.exists(logs.get(d["gate"], "")) else ""
        print(f"[heal] {d['gate']}: {d['category']} -> {d['action']} ({d['signature']})")
        if d["action"] == "rerun":
            rc, _, _ = run_gates(d["gate"], ROOT, os.path.join(a.out, "rerun"))
            r = {"status": "transient_cleared" if rc == 0 else "rerun_still_red_escalate"}
        elif d["action"] == "autofix":
            r = autofix(d, log_text, a, state, a.out)
        else:
            r = {"status": "escalated_to_human", "detail": "classified as a decision, not a defect"}
        r.update(decision=d, ts=now())
        state.setdefault(d["signature"], {"attempts": 0, "history": []})["history"].append(
            {"ts": r["ts"], "status": r["status"]})
        report.append(r)
        print(f"[heal]   => {r['status']}")
    with open(state_p, "w") as f:
        json.dump(state, f, indent=2)
    with open(os.path.join(a.out, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(a.out, "report.md"), "w") as f:
        f.write("# Heal report\n\n| gate | category | action | outcome | branch |\n|---|---|---|---|---|\n")
        for r in report:
            d = r["decision"]
            f.write(f"| {d['gate']} | {d['category']} | {d['action']} | **{r['status']}** | {r.get('branch', '')} |\n")
    with open(os.path.join(a.out, "cortex-events.jsonl"), "a") as f:
        for r in report:
            d = r["decision"]
            f.write(json.dumps({"schema": 1, "kind": "heal", "session": "ci-heal", "ts": r["ts"],
                                "summary": f"{d['gate']} {d['category']} -> {r['status']}"[:200],
                                "detail": json.dumps({"sig": d["signature"], "ids": d["ids"],
                                                      "branch": r.get("branch")})[:500]}) + "\n")
    ok = all(r["status"] in ("proposed", "transient_cleared", "dry_run") for r in report)
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
