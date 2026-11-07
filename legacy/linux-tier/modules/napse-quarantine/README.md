# napse-quarantine — Ring-0 line-rate quarantine enforcement (systemd-sysext)

> Fixes a LIVE finding (2026-07-03): a port scan from an iPhone enumerated every open port on
> this Pi 4 BEFORE the reactive detect→nft-drop loop (`napse-dpi` → `scan-responder.sh` →
> `nft add element`, a userspace `tail -F` + `exec nft` round trip) finished converging. This
> module attaches a tiny CO-RE **TC-bpf** program at clsact **INGRESS** on `wlan0` and `end0` —
> the earliest kernel point a quarantined source's packets can be stopped, before routing, before
> any netfilter/nftables hook, with none of the reactive path's userspace wakeup latency.

Canon: `docs/adr/0009-soc-brain-edge-cloud.md` (Ring-0 LPM/atomic-map-swap enforcement — this is
the exact-match, small-scale sibling of that design), `docs/adr/0005-unified-ebpf-detection.md`
(why `wlan0` is TC-bpf, never XDP), `crates/hookprobe-manifest/src/scan_responder.rs` (the
quarantine STATE this module enforces — it decides nothing on its own; C9).

## C9 — deterministic enforcement, no decisions here

`scan_responder::reconcile_quarantine`/`sweep_quarantine` (unchanged) DECIDE who is quarantined
and for how long, and persist that to `/var/lib/hookprobe/scan-quarantine.json`. This module only
mirrors that state into two kernel hash maps a TC-bpf program checks on every packet. No AI, no
judgment calls, no new policy — a pure enforcement mirror of an existing deterministic decision.

## Why a hash map, not the LPM-trie ADR 0009 sketches

ADR 0009 Decision 4's LPM-trie + atomic-double-buffer design is for the CLOUD `ip_risk_scores`
feed — bulk CIDR blocks pushed down in big batches. The scan-responder's quarantine set is the
opposite shape: a handful of EXACT observed addresses (single `/32`s, single MACs), added/removed
one at a time. `BPF_MAP_TYPE_HASH` keyed on the exact address is the right-sized structure; each
single-key update/delete is already atomic per the `bpf()` syscall, so the double-buffer machinery
(built for avoiding a bulk-rebuild stall) doesn't apply here. Revisit only if this map must ever
hold a CIDR-scale feed.

## Why nft stays (layering, not replacement)

- **BPF/TC (this module) is now the PRIMARY, line-rate layer.** Runs at clsact ingress,
  immediately after the driver hands off the skb — before routing, before any
  netfilter/nftables hook, no userspace round trip.
- **`nft` (`scan-responder.sh`, unchanged) is now the fallback/defense-in-depth layer.** If this
  loader ever fails to load/attach on a given boot (fail-open, see `loader/src/bpf.rs`), the
  device is not left with zero enforcement — only the (slower) one it has today.

## TC priority coexistence

`quarantine_ingress` claims **priority 1** at clsact ingress (`loader/src/bpf.rs`) — the lowest
number, evaluated first. A quarantine hit must win outright before any other classifier (the
detection/DPI-mirror TC program in `modules/napse-capture`) even sees the packet.
`modules/napse-capture/loader/src/bpf.rs`'s `napse_tc` attach was bumped from priority 1 to **10**
specifically so the two programs can never collide/clobber each other if both are ever enabled on
the same device (`.replace(true)` on an identical `(ifindex, priority, handle, direction)` tuple
silently overwrites whichever attached first).

## HONEST constraints (read before assuming this "fixes" scanning)

1. **Does NOT prevent the FIRST scan's disclosure.** A source must already be quarantined (by an
   earlier detection) before this program's maps have anything to match. A brand-new,
   never-before-seen scanner's opening probes still land before enforcement exists — this module
   makes the SECOND onward attempt from a flagged source instant/line-rate/unbypassable, it does
   not close the first-contact window. Closing that needs either faster detection (sub-scan
   latency) or a default-deny posture for unclassified devices. **Follow-up, not solved here.**
2. **`end0` uses TC-bpf, not native XDP**, even though `bcmgenet` is copy-mode-XDP-capable (ADR
   0009). Chosen for ONE uniform code path across `wlan0` (which has no native XDP option at
   all — ADR 0005 point 3) and `end0`. A native-XDP variant on `end0` would drop even earlier
   there; documented follow-up, not required by this specific (Wi-Fi/LAN-side) finding.
3. **Wi-Fi is TC-bpf, period** (ADR 0005 point 3): `brcmfmac`/`mac80211` has no native XDP hook at
   all. TC-bpf at clsact, seeing post-802.11-decap Ethernet frames, is the only in-kernel option —
   and it is what this module uses.
4. **Fail-open by design.** Any load/attach error just ends the process (`loader/src/bpf.rs`);
   nothing already running (the qdisc, nft, the datapath) is touched. `Restart=on-failure` retries
   on its own schedule. A partially-enforcing quarantine (one interface attached, one not) is still
   strictly safer than none, so a single bad interface doesn't abort the whole loader.

## Build → ship → run

1. **Build (CI host, has toolchain):** `make all` — compiles `quarantine.bpf.c` (CO-RE,
   `clang -target bpf`) and the native loader (Rust, `libbpf-rs`), staged under `sysext/`.
2. **Package:** the `sysext/` tree becomes a signed sysext OCI artifact (cosign), same mechanics
   as `napse-capture`.
3. **Ship:** merged at boot by `systemd-sysext.service`, covered by the image signature.
4. **Run:** supervisor sees `capabilities.capture == granted` → enables
   `napse-quarantine.service`.

## Cross-compile trail (aarch64, glibc — NOT musl)

Unlike most of this repo's static-musl binaries, this loader targets
**`aarch64-unknown-linux-gnu`** (dynamically linked against the Pi's real glibc), matching the
documented `hookprobe-evidence` cross-recipe (`builder/mkosi-arm64/build-arm64.sh:120`). Reasons,
found the hard way on this dev box and recorded here so nobody re-discovers them blind:

1. **musl target fails to link at all.** `libbpf`'s C source (vendored via `libbpf-sys`), compiled
   with a GLIBC cross compiler (`aarch64-linux-gnu-gcc`) while targeting Rust's musl ABI, produces
   object code full of glibc-only symbols (`__snprintf_chk`, `open64`/`fopen64`/`mmap64`, ...) that
   don't exist in musl → `undefined reference` at final link. Fix would need a genuine
   musl-targeting C cross-compiler (not present here); simpler to target the Pi's ACTUAL libc.
2. **`libbpf-rs`'s `vendored` feature (not just the default `vendored-libbpf`)** is required to
   vendor+build `libelf`/`zlib` from source too — this dev box has no aarch64 system
   `libelf`/`libz` to link against otherwise. Needs `autoconf automake libtool autopoint flex
   bison` (elfutils' build system) installed on the build host in addition to
   `aarch64-linux-gnu-gcc`.
3. **Ubuntu's `gcc-13-aarch64-linux-gnu` cross package ships glibc 2.39 headers**, newer than the
   Pi's actual runtime (Debian 12, glibc **2.36-9+deb12u14**). Compiling against 2.39 headers
   silently redirects `sscanf`/`fscanf`/`strtol`/`strtoull` to `__isoc23_*` symbols (a real glibc
   ≥2.38 ABI change, unconditional, independent of `_FORTIFY_SOURCE`) — producing a binary that
   fails at runtime on the Pi with `version 'GLIBC_2.38' not found`. Confirmed three ways: (a) a
   plain `--sysroot=` override wasn't enough (Ubuntu's cross-gcc hardcodes its own multiarch
   include dir ahead of the sysroot's), (b) `-isystem <sysroot>/usr/include` placed first still
   left a fallback path to the system headers reachable, (c) only `-nostdinc` + an explicit,
   complete `-isystem` list (gcc's own private headers + the sysroot's, nothing else) fully
   excludes the newer headers.
4. **Fix: an exact-version sysroot.** Exported `docker.io/arm64v8/debian:bookworm` (glibc
   `2.36-9+deb12u14` — an EXACT match to the live Pi) via `podman export`, then downloaded and
   extracted `libc6-dev_2.36-9+deb12u14_arm64.deb` (that slim image ships only the glibc runtime,
   not headers) and `linux-libc-dev_6.1.174-1_arm64.deb` (kernel UAPI headers, e.g.
   `linux/limits.h`) from `ftp.debian.org` on top of it. A wrapper script
   (`CC_aarch64_unknown_linux_gnu` / `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`) invokes
   `aarch64-linux-gnu-gcc -nostdinc --sysroot=<that tree> -isystem <gcc-private-include>
   -isystem <sysroot>/usr/include -isystem <sysroot>/usr/include/aarch64-linux-gnu
   -B/-L <sysroot's lib dirs>`. Verified: `objdump -T` on the resulting binary tops out at
   `GLIBC_2.34` — comfortably under the Pi's 2.36. This recipe is host-specific (paths under
   `/tmp`) and NOT wired into `Makefile`/CI as-is; CI should instead pin a matching
   `libc6-dev:arm64`/`linux-libc-dev:arm64` sysroot as a proper build input (e.g. a small
   container stage), the way this ad hoc trail did by hand.

## Live drop-test transcript (2026-07-03, Pi 4 @ 10.200.0.4)

Test source: a secondary IP alias (`10.200.0.9/28`) on the operator workstation's management-
subnet NIC — chosen so quarantining it could never sever the actual SSH session (`10.200.0.1`,
the real source, was never touched).

```
# BASELINE (pre-quarantine) — port 22 open, others closed-but-responsive (RST):
port 22:   Connection to 10.200.0.4 22 port [tcp/ssh] succeeded!
port 80:   nc: connect ... Connection refused
port 443:  nc: connect ... Connection refused
port 8080: nc: connect ... Connection refused
port 3000: nc: connect ... Connection refused

# quarantine 10.200.0.9 (write straight to the responder's own state file — no code path
# other than THIS module ever reads it, proving isolation from nft):
$ echo '[{"ip":"10.200.0.9","mac":null,"first_seen":...,"last_seen":...}]' \
    > /var/lib/hookprobe/scan-quarantine.json

# journal — reconciled within one poll cycle (500ms):
napse-quarantine: reconcile +1 -0

# --status confirms the map:
{"quarantined_ips":[{"hits":0,"ip":"10.200.0.9"}],"quarantined_macs":[],
 "stats":{"drop":0,"pass":744}}

# POST-QUARANTINE scan — ALL FIVE PORTS now silently time out (incl. the previously-open 22):
port 22:   nc: connect ... timed out
port 80:   nc: connect ... timed out
port 443:  nc: connect ... timed out
port 8080: nc: connect ... timed out
port 3000: nc: connect ... timed out

# --status proves the KERNEL did it — hit counter incremented:
{"quarantined_ips":[{"hits":10,"ip":"10.200.0.9"}],"quarantined_macs":[],
 "stats":{"drop":10,"pass":808}}

# nft cross-check — BOTH quarantine sets remain EMPTY the whole time (this is NOT nft):
$ nft list set inet hookprobe_quarantine quarantine_wan_ips   # { } (no elements)
$ nft list set inet hookprobe_quarantine quarantine_lan_ips   # { } (no elements)

# REVERT — empty the state file:
$ echo '[]' > /var/lib/hookprobe/scan-quarantine.json
napse-quarantine: reconcile +0 -1

# traffic flows again, identical to baseline:
port 22:   Connection to 10.200.0.4 22 port [tcp/ssh] succeeded!
port 80:   nc: connect ... Connection refused
port 443:  nc: connect ... Connection refused
port 8080: nc: connect ... Connection refused
port 3000: nc: connect ... Connection refused
```

## What's NOT tested in this pass (flagged, not hidden)

- **Live packet-level MAC-quarantine drop.** The MAC-packing logic is covered by a unit test
  (`state::tests::parses_mac_into_packed_u64_matching_bpf_side_packing`, byte-for-byte matching
  `quarantine.bpf.c`'s `pack_mac()`) and shares the identical enforcement code path proven live for
  the IP case — but a live packet test would have needed a source on a genuinely different NIC
  than the one carrying this SSH session (MAC-based blocking doesn't distinguish IP aliases on the
  same physical interface, so testing it here risked self-lockout). Next validation pass: exercise
  from a real second host on the LAN/Wi-Fi side.
- **XDP-native on `end0`.** Documented follow-up (constraint 2 above).
- **First-scan prevention.** Documented follow-up (constraint 1 above) — needs faster detection or
  a default-deny posture for unclassified devices, tracked separately from this fix.

## TODOs only CI / real hardware can close

- Pin the exact-version sysroot (glibc/kernel-headers matching each target platform) as a proper
  CI build input instead of the ad hoc `/tmp` trail above.
- `Makefile`'s `verify` target — load-test in a privileged CI VM per target arch (mirrors
  `napse-capture`'s same open TODO).
- Wire `napse-quarantine`'s pinned maps into a Mission Control Protect-workspace read-API (today
  `--status` is the only consumer).
