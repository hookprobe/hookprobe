#!/usr/bin/env python3
"""Product Cortex dev-time lifecycle capture (ADR 0013) — invoked by cortex-emit.sh from Claude Code
hooks. Reads the hook JSON on stdin and appends ONE immutable lifecycle event to the bus log.
Fail-open: any error is a silent no-op — a capture hook must never block the operator (C9: records,
never enforces)."""
import sys, json, datetime, re, os


def main():
    mode, log = sys.argv[1], sys.argv[2]
    try:
        h = json.load(sys.stdin)
    except Exception:
        return  # no/!JSON on stdin → nothing to capture
    sess = (h.get("session_id") or "unknown")[:16]
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")
    tool = h.get("tool_name", "")
    ti = h.get("tool_input", {}) or {}

    def emit(kind, summary, detail=""):
        ev = {"schema": 1, "kind": kind, "session": sess, "ts": ts,
              "summary": (summary or "")[:200], "detail": (detail or "")[:500]}
        with open(log, "a") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    if mode == "intent":
        p = (h.get("prompt") or "").strip()
        if p:
            emit("intent", p.splitlines()[0], p)
    elif mode == "change" and tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = ti.get("file_path") or ti.get("notebook_path") or "?"
        emit("change", f"{tool} {os.path.basename(fp)}", fp)
    elif mode == "gate" and tool == "Bash":
        cmd = ti.get("command", "")
        # only build/test/image commands are "gates" — not every shell call
        if re.search(r"\b(cargo (test|build|clippy|deny)|mkosi|smoketest|make-pi4|build-arm64|greenboot|npm run build"
                     r"|podman build|gates\.sh|validate\.sh|mc-e2e(-metal)?\.sh|heal\.py|repro\.sh)\b", cmd):
            emit("gate", cmd[:120], cmd)
    elif mode == "redgate" and tool == "Bash":
        cmd = ti.get("command", "")
        # OBSERVE-ONLY (escalating to confirm/block is a one-line change): record + notify.
        if re.search(r"(dd\s+.*of=/dev/sd|bootc\s+(install|upgrade)|hookprobe-flash|\bflash\b)", cmd):
            emit("red_action", f"RED: {cmd[:120]}", cmd)
            print(f"[cortex red-gate · observe] high-impact action recorded: {cmd[:80]}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail-open, always
