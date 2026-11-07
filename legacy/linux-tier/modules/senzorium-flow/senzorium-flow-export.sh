#!/usr/bin/env bash
# =============================================================================
# senzorium-flow-export — SOFTWARE flow capture (Senzorium "Observe").
#
# ZERO-TRUST / "everything is rogue": EVERY flow traversing this box is normalized to
# the common event schema and appended to /var/lib/hookprobe/flows — the stream NAPSE
# (the IDS Wasm module) consumes (module.yaml: read /var/lib/hookprobe/flows). No
# allowlist, no sampling: all AP/LAN client traffic is observed by the local SOC.
#
# This is the HONEST fallback capture path: the production fast path is the XDP capture
# sysext (napse-capture), but that needs a BPF build toolchain (clang/zig/bpftool) not
# present on the immutable image. The kernel conntrack table is already populated by the
# routed AP's NAT, so we read it: passive, out-of-band, ZERO connectivity risk.
#
# Each connection is emitted ONCE (on first observation) with its running counters. A
# subsequent XDP/AF_XDP capture can supersede this with per-packet features + entropy.
# =============================================================================
set -uo pipefail
FLOWS=${FLOWS:-/var/lib/hookprobe/flows}
INTERVAL=${INTERVAL:-5}
CT=${CT:-/proc/net/nf_conntrack}
MAX_LINES=${MAX_LINES:-50000}          # cap the append log (bounded retention)
SEEN=/run/hookprobe/senzorium-flow.seen
mkdir -p "$(dirname "$FLOWS")" /run/hookprobe
: > "$SEEN.tmp" 2>/dev/null || true
touch "$SEEN" 2>/dev/null || true

[ -r "$CT" ] || { echo "senzorium-flow: $CT unreadable (nf_conntrack not loaded?)" >&2; exit 1; }
# NOTE: conntrack byte/packet accounting (net.netfilter.nf_conntrack_acct) must be ON for the
# orig/resp byte+packet counts to be non-zero — shipped as sysctl.d/60-hookprobe-conntrack-acct.conf
# (this service is capability-less by design and cannot set sysctls itself).

emit_snapshot() {
  local ts; ts=$(date +%s.%3N 2>/dev/null || date +%s)
  # Parse conntrack: original 5-tuple + orig/reply bytes+packets + tcp state → napse JSON.
  awk -v ts="$ts" '
  {
    proto=""; state="SF"; osrc=odst=osport=odport="";
    nb=0; np=0; obytes=0; rbytes=0; opkts=0; rpkts=0; ns=0; nd=0; nsp=0; ndp=0;
    for (i=1;i<=NF;i++){ t=$i;
      if (t=="tcp"||t=="udp"||t=="icmp") { if(proto=="") proto=t }
      else if (t ~ /^[A-Z_]+$/ && t!="ASSURED" && t!="UNREPLIED") state=t;
      else if (t ~ /^src=/)    { if(ns++  ==0) osrc=substr(t,5) }
      else if (t ~ /^dst=/)    { if(nd++  ==0) odst=substr(t,5) }
      else if (t ~ /^sport=/)  { if(nsp++ ==0) osport=substr(t,7) }
      else if (t ~ /^dport=/)  { if(ndp++ ==0) odport=substr(t,7) }
      else if (t ~ /^bytes=/)  { if(nb++  ==0) obytes=substr(t,7); else if(nb==2) rbytes=substr(t,7) }
      else if (t ~ /^packets=/){ if(np++  ==0) opkts=substr(t,9);  else if(np==2) rpkts=substr(t,9) }
    }
    if (proto=="" || osrc=="" || odst=="") next;
    zs="OTH";
    if (proto=="tcp") {
      if (state=="ESTABLISHED"||state=="TIME_WAIT"||state=="CLOSE"||state=="FIN_WAIT"||state=="CLOSE_WAIT"||state=="LAST_ACK") zs="SF";
      else if (state=="SYN_SENT") zs="S0"; else if (state=="SYN_RECV") zs="S0"; else zs="OTH";
    } else zs="SF";
    uid=osrc"-"osport"-"odst"-"odport"-"proto;
    printf "%s\t{\"type\":\"conn\",\"ts\":%s,\"uid\":\"%s\",\"src_ip\":\"%s\",\"src_port\":%d,\"dst_ip\":\"%s\",\"dst_port\":%d,\"proto\":\"%s\",\"orig_bytes\":%d,\"resp_bytes\":%d,\"orig_pkts\":%d,\"resp_pkts\":%d,\"conn_state\":\"%s\"}\n", \
      uid, ts, uid, osrc, osport+0, odst, odport+0, proto, obytes+0, rbytes+0, opkts+0, rpkts+0, zs;
  }' "$CT"
}

while :; do
  # emit only flows not already seen (each connection once); refresh the seen set
  : > "$SEEN.new"
  while IFS=$'\t' read -r uid json; do
    [ -n "$uid" ] || continue
    echo "$uid" >> "$SEEN.new"
    grep -qxF "$uid" "$SEEN" 2>/dev/null && continue      # already emitted
    printf '%s\n' "$json" >> "$FLOWS"
  done < <(emit_snapshot)
  mv -f "$SEEN.new" "$SEEN" 2>/dev/null || true
  # bound the log
  if [ "$(wc -l < "$FLOWS" 2>/dev/null || echo 0)" -gt "$MAX_LINES" ]; then
    tail -n $((MAX_LINES/2)) "$FLOWS" > "$FLOWS.tmp" && mv -f "$FLOWS.tmp" "$FLOWS"
  fi
  sleep "$INTERVAL"
done
