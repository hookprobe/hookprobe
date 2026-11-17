# ADR 0066 — Sealed evidence export: replay the sealed evidence log over the enrolled PQ channel

**Status:** 🟡 **Proposed (2026-11-17).** The host library is written (`onboarding/enrollment/evidence-export/`);
**nothing is wired into heqk**. The wiring is a kernel change and needs the hooks in *Kernel interface* below.
Clauses are tagged **[realized]**, **[partial]** or **[vision]** (the ADR 0043/0044/0047 discipline).
**Deciders:** operator (ratification; whether public attacker addresses may leave the device, D3); os-architect
(D1, D4); security-auditor (D3, the privacy claim); verification-engineer (the gate in *Verification*).
**Relates to:** ADR 0044 D3 (B2 export), ADR 0007 (data at rest), ADR 0002 (crypto agility), ADR 0063 (gate spine;
the CI/CD ADR renumbered from 0052), `docs/design/heqk-control-plane.md`, `os/kernel/kernel/src/{export,exportwire,evlog,fslog,seal}.rs`.

## Context

What exists today **[realized]**:

- **The live export** (`export.rs`, M6 B2): an enrolled device drains the SOAR ring into a 64-event RAM queue and
  sends HQX1 v2 frames (`exportwire.rs`), sealed with `seal_record` on the Noise IK session (ML-KEM-768 + X25519)
  under `AD = "HQX2-export"`. Frames carry a per-boot event sequence, so the receiver sees every gap.
- **The sealed evidence log** (`evlog.rs`, #54): every detection is kept in the DataVolume, in an fslog ring of
  HQKSEAL1-sealed records under `HKDF(SRK, "HQ-evidence-log-v1")` (~90k detections, survives power cycles).

What is missing:

1. **Export never reads the log.** Events that arrive while the device is not enrolled, while the control plane is
   unreachable, or faster than 64 per heartbeat are counted as `lost` and never sent, although the log still has
   them.
2. **Nothing is acknowledged.** The device cannot know what the control plane has; there is no "synced through"
   mark, so there is nothing to resume from after an outage or a reboot.
3. **Privacy gap in the live stream.** For the IPv4 rules, `Rec.src` is the raw source address
   (`export::export_src` returns `ev.src` unchanged except for the MAC-keyed rules 121–123). An outbound detection
   (an infected LAN host) therefore sends the host's **internal address** off the device. HookProbe's privacy
   guarantee says export never carries local or internal addresses.

## Decision

### D1 — A separate, log-sourced stream: HQX3 **[partial]**

Records are read back from the sealed log and sent as **HQX3** frames (`evidence-export/src/wire.rs`), next to
the live HQX1 v2 stream, not instead of it. HQX3 numbers events by their place in the log, a cursor
`(log_seq, idx)`, because fslog's `log_seq` only grows across reboots. A frame states the range `[from, to)` it
accounts for, how many log records in it failed verification (`rejected`), how many were overwritten before they
were synced (`evicted`), and a QSECBIT sliding-window summary (count, span, min, max, mean, last). Up to 32
records of 20 bytes; 768 bytes of frame, one unfragmented datagram once sealed.

Associated data: `"HQX3-evidence"` (device → control plane) and `"HQX3-evidence-ack"` (control plane → device),
distinct from `"HQX2-export"`, so no record opens as another type.

### D2 — Synced, never deleted; cumulative acks **[partial]**

The control plane acks a batch with `(batch_seq, to)`. Acks are cumulative. The device keeps
`SyncState { synced, next_batch }` (32 bytes, sealed in the log) and moves `synced` only forward and only on an
ack that names a batch it sent with the same end position. Duplicates, never-sent batches and mismatched
positions are ignored and counted. Export **marks** evidence as synced; it never removes or rewrites a record.
Local retention stays the log's own ring, and records the ring overwrites before they were synced are reported
(`evicted`), never hidden.

Replay protection is in two layers: the session's explicit sequence + RFC 6479 window (`AntiReplayRx`) for
datagrams, and the forward-only cumulative ack for acks replayed inside the session.

### D3 — The privacy boundary is in the codec **[partial]**

`anon::anonymize` maps each event to what may leave the device: internal or special-purpose IPv4 sources (RFC 1918,
CGNAT, loopback, link-local, multicast, reserved, documentation ranges) become 0 and are marked `Redacted`;
MAC-derived sources (rules 121–123) become the same device-keyed pseudonym the live exporter uses, or `Redacted`
without a key; a public source (the attacker) is kept, unless the policy says `keep_public_src = false`. The record
type has no payload, destination, port or MAC field. `wire::serialize` refuses a record that breaks these rules,
and `wire::parse` refuses the same on the receiver, so a bug upstream cannot put an internal address on the wire.

**Operator decision needed:** whether public attacker addresses leave the device by default (proposed: yes, they
are the threat signature; `STRICT` is available).

### D4 — Offline is the normal case **[partial]**

Not enrolled: export does nothing and changes nothing (standalone is the default, never an error). Enrolled but
unreachable: the queue keeps its position and retries with a capped, deterministic exponential backoff (1 s to
5 min by default). An unacked batch times out (10 s) and the queue rewinds to `synced`; the same events go out in a
new batch and the receiver de-duplicates on the cursor. A late ack for the old batch still counts.

### D5 — The library holds no keys and opens no session **[realized]**

Decryption is the kernel's `seal::unseal` behind `SealOpener`; sealing frames onto the session is the kernel's
`RecordTx::seal` behind `Transport`; reading sectors is behind `SlotSource`. The library verifies each slot
(framing digest, ring placement, seal, layout, image sanity), rejects and counts anything that fails, and never
exports it.

## Kernel interface (needed to wire it; not built)

Nothing below exists in `os/kernel` yet. The library was written so the kernel can link it the way
`responder-sim` links `securechannel.rs`, by `#[path]`, or as a path dependency of the kernel crate (it is
`no_std`, `forbid(unsafe_code)`, and depends only on `boot-abi`). Which of the two is the os-architect's call:
the kernel workspace is "one self-contained workspace (never split it)", and a path dependency outside
`os/kernel` reverses the current direction of linking.

```rust
// evlog.rs: read access for the exporter
impl EvLog {
    /// Ring geometry for `SlotSource::geometry` (LogStore::nslots / next_seq are private today).
    pub fn geometry(&self) -> evidence_export::exporter::Geometry;
    /// Read the raw slot that holds record `seq` (fslog::LogStore::slot_lba(seq) + SealedStore::read_sector).
    pub fn read_slot<D: BlockDev>(&self, store: &SealedStore<D>, seq: u64, out: &mut [u8; 512]) -> Result<(), FsErr>;
    /// The opener: seal::unseal(&self.vek, &self.policy, blob, out).
    pub fn opener(&self) -> impl evidence_export::record::SealOpener + '_;
}

// fslog.rs: one framing parser instead of two copies
pub fn parse_record(sec: &[u8; SEC]) -> Option<(u64, u16, usize)>;    // make pub (today private)
pub const RT_EXPORT_SYNC: u16 = 6;  // a sealed 32-byte SyncState (evidence_export::queue::SyncState::encode)

// export.rs / controlplane.rs: the transport and the ack path
impl evidence_export::exporter::Transport for EnrolledTx { /* RecordTx::seal(ad, frame) + DGRAM_TAG + UDP */ }
// on an HQXR datagram that opens under AD_ACK: exporter.on_ack(pt) -> persist RT_EXPORT_SYNC on Advanced
// heartbeat: exporter.poll(now_ms, link, &mut evlog_source, &opener, &mut tx) -> persist on Some(state)
```

Also needed, separately:

- **Fix the live-stream privacy gap** (Context 3): `export_src` should apply `anon::is_internal_v4` (or the whole
  `anonymize`) to the IPv4 rules. This changes `export.rs` only.
- **The tri-state class is not in the 16-byte log image**, so HQX3 records carry `class = 0`. Adding it means a
  new image layout (and a new record type, `RT_EVIDENCE_C`); out of scope here.
- **Attack paths and Wasm module identity** are not in the log image either (rule id, severity and verdict are).
  Exporting them needs the same image change.
- **Unflushed events** (the RAM batch, up to 60 s) reach HQX3 only once `evlog` writes the record.
- **The receiver**: `responder-sim/src/export_rx.rs` should accept HQX3 under `AD_FRAME`, de-duplicate on the
  cursor and answer with an ack under `AD_ACK`.

## Verification

- `cd onboarding/enrollment/evidence-export && cargo test` runs the unit tests; CI runs them in gate g1
  (`tools/ci/gates.sh`, "host tests: evidence-export"). Among them are the three asked for:
  privacy redaction (`anon::internal_addresses_are_redacted`, `wire::codec_refuses_internal_addresses`,
  `exporter::exported_frames_carry_no_internal_addresses`), tampered-record rejection
  (`record::tampered_records_are_rejected`, `exporter::tampered_record_is_reported_not_exported`), and offline
  retention (`queue::not_enrolled_is_idle`, `queue::down_backs_off_and_keeps_position`,
  `exporter::offline_queue_retains_everything`, `exporter::lost_ack_resends`).
- The tests use a stand-in sealer (`testutil::TestOpener`), not HQKSEAL1: the library treats opening as opaque.
  The HQKSEAL1 path is proven once the kernel wiring lands, by a new `[P-evexport]` phase in `validate.sh` that
  exports a sealed log over the loopback session and checks the received set.
- `os/kernel` is untouched by this ADR's code, so `validate.sh` is unaffected.

**Evidence (2026-11-17):** CI gate g1 on hookprobe/hookprobe#1272 (Actions run 44178705052, job 134376924553)
compiled the library with stable Rust, with no warnings, and passed **31 of 31** unit tests, the three sets above
included. This proves the library against its stand-in sealer only; the HQKSEAL1 path and the on-device export
stay unproven until the kernel wiring and its `[P-evexport]` phase land.
