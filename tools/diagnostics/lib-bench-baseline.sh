# shellcheck shell=bash
# Gap-fix plan E3: a check that changes the bench configuration puts the bench back on its own setup before it starts
# and again when it exits (pass, fail or interrupt), so the next check — in a regression run or by hand — starts from
# the same state. Source it AFTER the check has set its own EXIT trap (the baseline is chained in front of that trap):
#   . "$(dirname "$0")/lib-bench-baseline.sh"; bench_baseline_wrap "$KEY" "$LOG" "$MC"
# BENCH_BASELINE=0 skips both (a runner that does its own baseline, or a debug session that wants the changed state).
bench_baseline_wrap() {
  [ "${BENCH_BASELINE:-1}" = 0 ] && return 0
  local here prev
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  BB_CMD=(bash "$here/cm5-bench-baseline.sh" "$1" "$2" "${3:-https://192.168.200.146}")
  echo "  [bench baseline] before: $("${BB_CMD[@]}" 2>&1 | tail -1)"
  prev=$(trap -p EXIT | sed -e "s/^trap -- '//" -e "s/' EXIT\$//")
  # shellcheck disable=SC2064
  trap "echo \"  [bench baseline] after: \$(\"\${BB_CMD[@]}\" 2>&1 | tail -1)\"; $prev" EXIT
}
