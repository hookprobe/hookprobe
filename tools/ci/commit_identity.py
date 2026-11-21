#!/usr/bin/env python3
"""Commit identities must not expose a personal or contact email — only GitHub noreply addresses.

Why (2026-11-21): qsecbit@hookprobe.com — the project's public CONTACT address — leaked into commit metadata.
GitHub web merges by an account whose commit email is that address made main's tip carry it; a session then
copied the tip's email into its own commits (`-c user.email=$(git log -1 --format=%ae origin/main)`), so it spread
into #1409/#1410. History was rewritten to noreply addresses; this check keeps it that way. It runs on every PR
(.github/workflows/ci.yml job `identity`, required through ci-ok) and in the local pre-push hook.

Allowed in author / committer / Co-authored-by:
  <id>+<login>@users.noreply.github.com  and  <login>@users.noreply.github.com   (any account)
  noreply@github.com                                                            (GitHub's own web-merge committer)

    commit_identity.py <base>..<head>          check the commits in a range (CI)
    commit_identity.py --not-remotes <sha>     check <sha>'s commits not yet on any remote (pre-push, new branch)
"""
import re
import subprocess
import sys

ALLOWED = re.compile(r"^(?:\d+\+)?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[bot\])?@users\.noreply\.github\.com$|^noreply@github\.com$")
# Co-authored-by may also name a role noreply address (not a person's inbox): a colleague's tool trailer such as
# "Claude <noreply@anthropic.com>" is their choice (operator 2026-11-20) and exposes nobody.
ROLE_NOREPLY = re.compile(r"^no-?reply@[a-z0-9.-]+\.[a-z]{2,}$", re.I)
COAUTHOR = re.compile(r"(?im)^\s*co-authored-by:\s*(.*?)\s*<([^>]*)>\s*$")
SEP = "\x1f"


def commits(args):
    fmt = SEP.join(["%H", "%an", "%ae", "%cn", "%ce", "%B"]) + "\x1e"
    out = subprocess.run(["git", "log", f"--format={fmt}", *args], capture_output=True, text=True, check=True).stdout
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, an, ae, cn, ce, body = rec.split(SEP, 5)
        yield sha, an, ae, cn, ce, body


def problems(records):
    out = []
    for sha, an, ae, cn, ce, body in records:
        for role, name, email in (("author", an, ae), ("committer", cn, ce)):
            if not ALLOWED.match(email):
                out.append(f"{sha[:10]} {role} {name} <{email}>")
        for name, email in COAUTHOR.findall(body):
            if not (ALLOWED.match(email) or ROLE_NOREPLY.match(email)):
                out.append(f"{sha[:10]} Co-authored-by {name} <{email}>")
    return out


def main(argv) -> int:
    if len(argv) == 2 and argv[0] == "--not-remotes":
        args = [argv[1], "--not", "--remotes"]
    elif len(argv) == 1 and ".." in argv[0]:
        args = [argv[0]]
    else:
        print(__doc__)
        return 2
    bad = problems(commits(args))
    if bad:
        print("COMMIT IDENTITY: these commits expose a non-noreply email (use your GitHub noreply address,", file=sys.stderr)
        print("e.g. git config user.email <id>+<login>@users.noreply.github.com, then rewrite them):", file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 1
    print("commit identity: ok (noreply addresses only)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
