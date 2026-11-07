#!/bin/sh
# dnsxai-feed.sh — extract DNS query domains from the flow stream (type=dns records) → one domain per
# line for dnsxai. `fflush()` keeps it streaming (no block buffering). Pure awk, no jq.
#
# The query name is attacker-controlled: a crafted name with an embedded quote/backslash would desync a
# naive `[^"]+` extractor (truncated domain). So we VALIDATE the extracted value is a plausible domain
# (label charset + length) and drop anything else — no malformed data reaches dnsxai.
# Emit ONE bare domain per line. NOTE (2026-07-06 F3 fix): an earlier attempt to append
# `<TAB>src_ip` (EDR #10 device attribution) NEUTERED DGA scoring — the deployed dnsxai.wasm does
# not split shape-2 input, so `domain<TAB>ip` tokenized to a short/benign label and every verdict
# scored 0.0. Device attribution is instead sourced downstream from the flow record's own `src_ip`
# in the evidence graph, so the feed stays bare. Re-enable shape-2 here ONLY after the dnsxai module
# implements + tests tab-splitting (proper F3 fix).
#
# TA1 (2026-07-17): the image's `awk` is **mawk**, which BLOCK-BUFFERS stdin (its own input reader —
# `stdbuf` can't fix it), so on a low-DNS-rate device a sparse query sat unprocessed until the buffer
# filled → dnsxai starved. `mawk -W interactive` = line-buffered input (+ unbuffered output). `fflush()`
# (below) covers the output side. Same fix as aegis-feed.sh; drop `-W interactive` only if awk→gawk.
exec mawk -W interactive '
/"type":"dns"/ {
  if (match($0, /"query":"[^"]*"/)) {
    q = substr($0, RSTART+9, RLENGTH-10)
    if (q ~ /^[A-Za-z0-9._-]+$/ && length(q) >= 1 && length(q) <= 253) { print q; fflush() }
  }
}
'
