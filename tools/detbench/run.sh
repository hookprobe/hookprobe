#!/usr/bin/env bash
# detbench/run.sh — detection-accuracy benchmark (readiness 4.1): replay a labelled corpus through the real
# heqk detection pipeline under QEMU and print a per-rule table (alerts per label; the first label is benign,
# so its column is the false-positive count).
#   tools/detbench/run.sh CORPUS.img [report.md]
# Build a corpus: tools/detbench/gen-attacks.py DIR ; tools/detbench/pcap2hqdb.py OUT.img benign:bg.pcap scan:DIR/portscan.pcap ...
set -u -o pipefail
IMG="${1:?corpus image (pcap2hqdb.py)}"; REP="${2:-}"
HERE=$(cd "$(dirname "$0")" && pwd); K=$(cd "$HERE/../../os/kernel" && pwd)
( cd "$K" && CARGO_TARGET_DIR=target/detbench cargo build --features netsvc,securechannel,detbench >/tmp/detbench-build.$$ 2>&1 ) || { tail -20 /tmp/detbench-build.$$; exit 2; }
KERN="$K/target/detbench/aarch64-unknown-none-softfloat/debug/kernel"
RAW=$(mktemp); trap 'rm -f "$RAW"' EXIT
timeout 1800 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
  -drive file="$IMG",format=raw,if=none,id=hd0,readonly=on -device virtio-blk-device,drive=hd0 \
  -kernel "$KERN" 2>&1 | tr -d '\r' > "$RAW"; QRC=${PIPESTATUS[0]}
OUT=$(grep -a "\[DETBENCH\]" "$RAW")
if ! grep -q "DETBENCH\] DONE" <<<"$OUT"; then
  # Show WHY: the exit status (124 = the 1800 s timeout) and the tail of the raw console, not just the
  # [DETBENCH] lines — an early panic or a QEMU error is otherwise invisible.
  echo "no DONE marker — replay did not finish (qemu exit $QRC$([ "$QRC" = 124 ] && echo ', timed out after 1800 s'))"
  echo "$OUT"; echo "--- last 40 console lines ---"; tail -n 40 "$RAW"; exit 1
fi
python3 - "$OUT" "$REP" <<'PY'
import re, sys
out, rep = sys.argv[1], sys.argv[2]
labels, rows, frames = [], [], {}
for l in out.splitlines():
    m = re.search(r"label=(\S+) frames=(\d+) drops=(\d+)", l)
    if m:
        labels.append(m.group(1)); frames[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    m = re.search(r'rule=(\d+) msg="([^"]*)"(.*)', l)
    if m:
        rows.append((int(m.group(1)), m.group(2), dict((k, int(v)) for k, v in re.findall(r"(\S+)=(\d+)", m.group(3)))))
md = ["| label | frames | dropped |", "|---|---|---|"] + [f"| {l} | {frames[l][0]} | {frames[l][1]} |" for l in labels]
md += ["", "| rule | " + " | ".join(labels) + " |", "|---" * (len(labels) + 1) + "|"]
for rid, msg, c in rows:
    md.append(f"| {rid} {msg} | " + " | ".join(str(c.get(l, 0)) for l in labels) + " |")
benign = labels[0] if labels else "?"
fp = sum(c.get(benign, 0) for _, _, c in rows)
missed = [l for l in labels[1:] if not any(c.get(l, 0) for _, _, c in rows)]
md += ["", f"**False positives on `{benign}`:** {fp} alerts over {frames.get(benign, (0, 0))[0]} frames.",
       f"**Attack classes with no alert at all:** {', '.join(missed) if missed else 'none'}."]
text = "\n".join(md)
print(text)
if rep:
    open(rep, "w").write(text + "\n")
PY
