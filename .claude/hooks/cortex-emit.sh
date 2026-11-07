#!/usr/bin/env bash
# cortex-emit.sh <mode> — Product Cortex dev-time lifecycle capture (ADR 0013).
#
# Called by Claude Code hooks (UserPromptSubmit / PostToolUse / Stop / PreToolUse). Reads the hook
# JSON on stdin and appends ONE immutable lifecycle event to the dev-time bus log — or, on Stop,
# folds the log into the evidence graph. This is how "every prompt→build interaction feeds the
# Cortex" becomes literally true on this box: the HARNESS emits deterministically, so it never
# depends on the AI remembering to log (C9: the harness records; it does not enforce).
#
# ALWAYS fail-open: a capture hook must never block the operator's work. Every path exits 0.
#
#   modes: intent (UserPromptSubmit) · change (PostToolUse Write/Edit) · gate (PostToolUse Bash)
#          · redgate (PreToolUse Bash, observe-only) · ingest (Stop → fold into the graph)
set +e
MODE="${1:-}"
ROOT="${CLAUDE_PROJECT_DIR:-$PWD}"
HOOKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$ROOT/.claude/cortex"
LOG="$DIR/events.jsonl"
DB="$DIR/lifecycle.db"
mkdir -p "$DIR" 2>/dev/null

# Capture: the hook JSON on stdin flows straight into the python (NOT a heredoc — a heredoc would
# hijack stdin and swallow the payload). One event appended per matching interaction.
python3 "$HOOKDIR/cortex_emit.py" "$MODE" "$LOG" 2>/dev/null

# Stop hook: fold captured events into the dev graph, then clear the working log (ingest is
# idempotent — the events now live in the graph). Uses whichever evidence binary is already built.
if [ "$MODE" = "ingest" ] && [ -s "$LOG" ]; then
    BIN=""
    for c in "$ROOT/target/release/hookprobe-evidence" "$ROOT/target/debug/hookprobe-evidence" \
             "$(command -v hookprobe-evidence 2>/dev/null)"; do
        [ -x "$c" ] && BIN="$c" && break
    done
    if [ -n "$BIN" ] && "$BIN" --db "$DB" --ingest-lifecycle "$LOG" >/dev/null 2>&1; then
        : > "$LOG"   # folded into the graph; reset the working log
    fi
fi
exit 0
