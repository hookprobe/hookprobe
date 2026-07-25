# napse-l2guard — Ring-0 line-rate malformed-frame / malformed-ARP drop (systemd-sysext)

> Replaces the honest stub `render_frame_drop_todo` left in
> `crates/hookprobe-manifest/src/l2_responder.rs` when ADR 0020 Phase-1a's storm-control half
> landed: nft can express a per-source RATE cap (real, see `render_storm_control`) but cannot
> express byte-level frame validation or "these two packet fields disagree with each other" —
> exactly what a malformed/fuzzed frame or a spoofed ARP sender-mac needs. This module is that
> missing TC-bpf clsact-**ingress** hook: it re-parses raw frame bytes exactly like
> `napse_loader::dpi` (modules/napse-capture/loader/src/dpi.rs) already does, in the kernel, and
> returns `TC_ACT_SHOT` for precisely the conditions that module's detectors flag as
> `l2_responder::L2Verdict::FrameDrop`.

Canon: `crates/hookprobe-manifest/src/l2_responder.rs` (the verdict this module enforces — it
decides nothing on its own, C9), `modules/napse-capture/loader/src/dpi.rs` +
`modules/napse-capture/loader/src/l2guard.rs` (the EXACT predicates this program mirrors),
`modules/napse-quarantine` (the sibling Ring-0 TC-bpf attach pattern this module's `loader/`
directly mirrors — see "why a separate module" below).

## C9 — deterministic enforcement, no decisions here

`napse_loader::dpi::frame_anomaly_reason` / `ArpObs::is_malformed` / `ArpObs::eth_mismatch`
(unchanged) already DEFINE what "malformed" means. This module's BPF program (`bpf/l2guard.bpf.c`)
re-implements exactly those same checks against the SAME field offsets/bit tests, in C, at the
earliest kernel point a bad frame can be stopped. No new policy, no judgment call, no AI — a pure
enforcement mirror of an already-deterministic definition.

## Why a SEPARATE module from `napse-quarantine` (not a mode of its loader)

The task that produced this module explicitly required the two stay separate programs/attaches,
and the reasoning holds up structurally, not just as an instruction:

- **Different question, different anti-spoof shape.** `napse-quarantine` drops a packet because of
  **who** (a spoofable claimed MAC/IP) a prior userspace decision already quarantined — it mirrors
  *external, per-identity state* (`/var/lib/hookprobe/scan-quarantine.json`) into two hash maps and
  needs an ongoing reconcile loop to stay in sync with that state. `napse-l2guard` drops a packet
  because of **what** it structurally is — a property of the frame itself, entirely self-contained
  in the compiled BPF bytecode, with **no external state to reconcile at all**. Folding a stateless,
  no-reconcile-loop concern into a loader whose entire structure (`state.rs`, the poll loop,
  `PlaneIfindexes`) exists to serve a *stateful* one would blur exactly the anti-spoof distinction
  `crates/hookprobe-manifest/src/l2_responder.rs`'s module doc calls "even MORE binding" at L1/L2
  than at the port-scan layer.
- **A DIFFERENT capability surface, for the same reason `crates/hookprobe-manifest/src/
  l2_responder.rs`'s `L2Verdict` has exactly two variants and no third, identity-quarantine-reaching
  one.** Keeping frame-drop enforcement in its own module.yaml/systemd unit/artifact set makes it
  structurally impossible for a future edit to a shared loader to accidentally let a "malformed
  frame" finding grow a code path into `scan_responder::reconcile_quarantine` (the persisted,
  escalating-hold, identity-keyed block) — there simply is no shared code for that edit to happen in.
- **Independent operability.** `napse-quarantine`'s own README documents it as fail-open and
  independently restartable; `napse-l2guard` needed to be independently attachable/disableable too
  (e.g. a device that wants malformed-frame drop but has disabled identity quarantine for some
  reason, or vice versa) — a shared binary would force both concerns to succeed or fail together at
  the process level, which they have no reason to.

What IS mirrored, deliberately, because it's the RIGHT convention, not incidental: the `loader/`
crate split (pure logic outside `feature = "bpf"`, libbpf glue inside it), the `granted()`
self-gate pattern (reusing `ddos_mitigation`, not inventing a new capability token), the ADR 0016
Fix C `verify_own_artifacts` gate, the Makefile's aarch64-gnu cross-recipe, and the fail-open
contract. This is "match repo convention" applied at the right grain: share the *shape*, keep the
*concern* separate.

## The shared-seam anti-drift discipline (the task's non-negotiable "critical" requirement)

The single biggest risk in this design is **drift**: the BPF program (C) and the detector
(`dpi.rs`, Rust) each independently define "malformed", and if they ever disagree, either the
detector alerts on a frame this program silently lets through (an enforcement gap nobody notices —
alerts still fire, but nothing was actually dropped), or this program drops a frame the detector
would call benign (an availability regression on real traffic). Three things keep them in
lockstep:

1. **`bpf/l2guard.h`** documents, in its own doc comment, that every numeric constant it defines
   (`L2GUARD_MIN_FRAME_LEN`, `L2GUARD_MAX_FRAME_LEN`, the ARP htype/ptype values, the VLAN
   ethertype/reserved-vid) MUST equal the corresponding `napse_loader::dpi` constant.
2. **`loader/src/predicates.rs`** is the enforceable proof: `bpf_would_drop()` is a line-for-line
   Rust mirror of `l2guard.bpf.c`'s decision logic, with every branch cross-referenced by comment
   to the exact block it mirrors. Its test module asserts, for a battery of fixture frames (benign,
   runt, oversized, multicast-source-MAC, double-VLAN, reserved-VLAN-id, well-formed ARP, malformed
   ARP, ARP eth-mismatch, a lone gratuitous ARP), that this mirror agrees EXACTLY with
   `napse_loader::dpi::frame_anomaly_reason` / `ArpObs::is_malformed` / `ArpObs::eth_mismatch` — the
   REAL production detector functions, imported directly (a dev-dependency on the `napse-loader`
   crate), never a second hand-copied definition. A separate test
   (`l2guard_h_constants_match_dpi_rs_exactly`) pins the numeric constants themselves.
3. Because this dev box has no root/CAP_BPF (see "honest constraints" below), the compiled `.bpf.o`
   itself cannot be load-tested here — `predicates.rs`'s Rust mirror is therefore the STRONGEST
   available proof of parity in this pass, not a formality. A CI/hardware pass with a veth+tc
   harness (see `Makefile`'s `verify` target) would be the stronger, direct proof; until then, any
   edit to `l2guard.bpf.c` should get a matching edit to `predicates.rs` in the SAME commit, and the
   test suite is what catches a human forgetting to.

## Drop predicates (mirrors `dpi::frame_anomaly_reason_local` / `ArpObs`, in this exact order)

| # | Condition | dpi.rs source | Verdict this enforces |
|---|---|---|---|
| 1 | shorter than a bare Ethernet header (`skb->len < 14`) — always a genuine drop | `frame_anomaly_reason_local` check #1 | `l2_malformed` |
| 1b | runt frame (`14 <= skb->len < 60`), UNLESS it fully, structurally parses as a complete ARP or IPv4 TCP/UDP/ICMP packet at ITS OWN protocol-correct minimum length (42 bytes for ARP, 34 for bare IPv4/ICMP, 54 for a bare TCP segment, 42 for a bare UDP datagram — **2026-07-07 fix**, see below; there is no single flat length floor here anymore) | `frame_anomaly_reason_local` check #2 (`is_well_formed_ipv4_or_arp` in the BPF) | `l2_malformed` |
| 2 | oversized frame (`skb->len > 1522`) | `frame_anomaly_reason_local` check #3 | `l2_malformed` |
| 3 | source MAC multicast/group bit set | `frame_anomaly_reason` check #4 | `l2_malformed` |
| 4 | 802.1Q tag too short to contain itself, OR double/stacked tag (QinQ), OR reserved VLAN id 0xFFF | `frame_anomaly_reason` check #5 | `l2_malformed` |
| 5 | ARP structural anomaly (non-standard htype/ptype/hlen/plen) | `ArpObs::is_malformed` | `arp_spoof` / `malformed_fields` |
| 6 | ARP sender-mac ≠ Ethernet frame's own source mac | `ArpObs::eth_mismatch` | `arp_spoof` / `eth_mismatch` |

**Deliberately NOT covered** (out of this program's scope — both `l2guard.bpf.c`'s and
`predicates.rs`'s doc comments say so explicitly, matching the task's own bullet list): ARP
binding flip-flop and gratuitous-ARP flood. Both need cross-packet HISTORY (a per-IP binding
table / a per-source rate window) — a genuinely different, stateful engineering problem from "is
this ONE frame structurally bad". Gratuitous-ARP flood is already mitigated (rate-limited, real
enforcement) by `l2_responder::render_storm_control`'s nft meter; binding flip-flop remains
alert-only. Extending this program with a pinned per-IP state map to also cover binding flip-flop
is a real, separate follow-up, not a gap silently swallowed here.

**Also deliberately NOT checked**: the ARP opcode's value. The task's own prose mentions "bad
hlen/plen/op", but the actual, authoritative predicate (`dpi::ArpObs::is_malformed`) does **not**
validate opcode — only htype/ptype/hlen/plen. Adding an opcode check here without first adding it
to `dpi.rs` would itself BE the drift bug this module exists to prevent, so this program
deliberately matches the real code, not the summary prose that described it.

## TC priority coexistence

`l2guard_ingress` claims **priority 5** at clsact ingress (`loader/src/bpf.rs`) — strictly between
`napse-quarantine`'s priority 1 (identity quarantine, evaluated first) and `napse-capture`'s
priority 10 (the DPI mirror). The two Ring-0 drop programs check independent conditions (a
malformed frame is dropped regardless of whether its source also happens to be quarantined, and
vice versa), so their relative order does not affect correctness — priority 5 simply leaves room
on either side for a future Ring-0 program without renumbering either existing one.

## HONEST constraints (read before assuming this "fixes" every malformed frame)

1. **Compile-proven, NOT attach-verified on real hardware in THIS pass.** `clang -target bpf`
   compiles `l2guard.bpf.c` clean (0 errors/0 warnings) on this dev box, and the object is
   byte-identical whether compiled with `-D__TARGET_ARCH_arm64` or `-D__TARGET_ARCH_x86` (same
   proof `napse-quarantine`'s module.yaml documents for its own object). A verifier smoke-load
   (`bpftool prog load`) was attempted and failed with **`Operation not permitted`** — this dev
   box's user has no root/CAP_BPF (confirmed: `unprivileged_bpf_disabled=2`, no passwordless
   sudo). This is the missing-privilege case, not a program defect, and is the SAME honest posture
   `napse-quarantine` carried before its first live Pi test (2026-07-03) — see this repo's
   `docs/BuildPlan.md` changelog for that precedent. **Next validation pass, on hardware with
   root/CAP_BPF: `bpftool prog load` (or the loader itself, run as root) to prove the verifier
   accepts it, then a real drop test (a crafted runt/malformed-ARP frame from a second host) the
   same way `modules/napse-quarantine/README.md`'s live-drop-test transcript proves its program.**
2. Deliberately does not cover ARP binding flip-flop / gratuitous-ARP flood (see the predicates
   table above) — stateful, out of scope for this stateless frame-level program.
3. `end0` uses TC-bpf, not native XDP, for the same ONE-uniform-code-path reason
   `napse-quarantine`/ADR 0005 document: `wlan0`/brcmfmac has no native XDP option at all.
4. **Fail-open by design.** Any load/attach error just ends the process (`loader/src/bpf.rs`);
   nothing already attached (napse-quarantine's hook, the DPI mirror, nft) is touched.
   `Restart=on-failure` retries on its own schedule.

## Build → ship → run

1. **Build (CI host, has toolchain):** `make all` — compiles `l2guard.bpf.c` (CO-RE,
   `clang -target bpf`) and the native loader (Rust, `libbpf-rs`), staged under `sysext/`.
2. **Package:** the `sysext/` tree becomes a signed sysext OCI artifact (cosign), same mechanics
   as `napse-quarantine`/`napse-capture`.
3. **Ship:** merged at boot by `systemd-sysext.service`, covered by the image signature.
4. **Run:** the unit self-gates (`loader/src/main.rs`'s `granted("ddos_mitigation")`) — preset
   enabled everywhere, active only where the platform manifest grants that capability.

## Cross-compile trail (aarch64, glibc — NOT musl)

Identical rationale and recipe to `modules/napse-quarantine/README.md`'s documented trail (same
`libbpf-rs` `vendored` feature needing autotools on this dev box, same exact-version Debian 12
bookworm arm64 glibc-2.36 sysroot at `/tmp/bookworm-arm64-sysroot` + the `/tmp/aarch64-sysroot-gcc`
wrapper) — not re-derived here. Verified this pass: `objdump -T` on the cross-built loader tops out
at `GLIBC_2.34`, comfortably under the Pi's 2.36.

## What's proven in THIS pass (2026-07-05)

- `clang -target bpf` compiles `l2guard.bpf.c` clean, both `-D__TARGET_ARCH_x86` and
  `-D__TARGET_ARCH_arm64` — byte-identical output either way.
- `cargo test -p napse-l2guard` — 16/16 green, including the full `predicates.rs` anti-drift suite
  (every fixture frame agrees between the BPF mirror and the real `napse_loader::dpi` detector) and
  the ADR 0016 artifact-digest self-verify regression tests.
- The native loader cross-builds clean for BOTH `x86_64-unknown-linux-gnu` and
  `aarch64-unknown-linux-gnu --features bpf`; `module.yaml`'s two `role: loader` digests and its
  one arch-less `role: bpf-object` digest are REAL sha256 of those exact built bytes (via
  `hookprobe-supervisor --write-artifact-digests napse-l2guard`, the arm64 pass run under
  `qemu-aarch64-static` against the bookworm sysroot — same precedent
  `modules/napse-quarantine/module.yaml`'s comment documents), never hand-`sha256sum`'d.

## What's NOT tested in this pass (flagged, not hidden)

- **Verifier load / real packet-level drop on hardware.** No root/CAP_BPF on this dev box — see
  "honest constraints" above. Tracked as the next validation pass, same as `napse-quarantine`'s own
  pre-live-test posture.
- **ARP binding flip-flop / gratuitous-ARP-flood enforcement.** Out of scope by design (stateful);
  gratuitous flood is separately rate-limited by `l2_responder`'s existing nft meter.

## TODOs only CI / real hardware can close

- `Makefile`'s `verify` target — load-test in a privileged CI VM or on real hardware per target
  arch, feeding the SAME fixture frames `loader/src/predicates.rs`'s tests assert on, and confirm
  `TC_ACT_SHOT`/`TC_ACT_OK` match per fixture.
- A live drop-test transcript on real hardware (mirrors `napse-quarantine/README.md`'s).
- Wire `napse-l2guard`'s pinned stats map into a Mission Control Protect-workspace read-API (today
  `--status` is the only consumer, same limitation `napse-quarantine` currently has).
