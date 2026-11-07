#!/bin/sh
# aegis-feed.sh — derive per-IP reflex events for aegis-guard from NAPSE ALERTS:
#   reflex,<src_ip>,<confidence>,<velocity>   (velocity 0 for now)
# aegis-guard maps the score → OBSERVE / JITTER / SHADOW / DISCONNECT.
#
# TA1 (2026-07-17 field root-cause): the image's `awk` is **mawk**, which BLOCK-BUFFERS its STDIN
# (its own input reader, not libc stdio — so `stdbuf` cannot fix it). On a quiet, well-defended
# network — the COMMON case — a sparse NAPSE alert sat in mawk's input buffer and was NEVER processed
# until the buffer filled (or EOF), so aegis-guard was starved and `aegis-verdicts` stayed empty: the
# ADR-0023 reflex ENFORCEMENT path silently dead on any low-traffic device. A busy device only
# "worked" because alert volume filled the buffer — which is exactly why this masqueraded as an
# "A72-only" bug (quiet Pi4 vs busy CM5). `mawk -W interactive` forces LINE-buffered input (+ unbuffered
# output), so each alert is processed the instant it arrives. `fflush()` (below) remains for the output
# side. If the image's awk provider ever changes to gawk, drop `-W interactive` (gawk streams natively).
exec mawk -W interactive '
{
  # only act on actual NAPSE alerts (they carry a rule_id) — not arbitrary events on the stream.
  if ($0 !~ /"rule_id"/) next
  if (!match($0, /"src_ip":"[^"]+"/)) next
  ip = substr($0, RSTART+10, RLENGTH-11)
  if (ip ~ /[",]/) next            # a comma/quote in the IP would desync the CSV downstream
  c = "0.5"
  # a SINGLE well-formed float (rejects 1.2.3 etc. that would garble the CSV field)
  if (match($0, /"confidence":[0-9]+\.?[0-9]*/)) c = substr($0, RSTART+13, RLENGTH-13)
  print "reflex," ip "," c ",0"; fflush()
}'
