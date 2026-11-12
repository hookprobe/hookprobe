# Fuzz evidence — SEC-02 (2026-11-10)

`tools/fuzz/run.sh 300`: coverage-guided libFuzzer (cargo-fuzz 0.13.2, nightly 2026-07-17), 300 s per target. All targets compile the SAME source files the device runs:

- `hal`: POLICY.TXT, WAN.TXT, frame facts / VLAN, SDIO glom, A/B slot derivation.
- `boot-abi`: the signed-image / OTA verifier header (`payload_header`).
- Kernel crate via `tools/fuzz/heqk-kernel` (`#[path]` to `os/kernel/kernel/src/*.rs`):
  - `http_req`: Mission Control request parser, query string and form bodies — every POST including uploads.
  - `dns_wire`: names with compression pointers, client queries.
  - `tls_hello`: ClientHello → JA4 / SNI.
  - `frame_meta`: the IDS frame classifier.

These parsers were moved verbatim into pure modules (`httpreq.rs`, `dnswire.rs`, `tlshello.rs`) that the original modules re-export. If a parser grows a kernel dependency, the harness build fails.

Fixed-layout, MAC/digest-verified-before-decode stores (owner-journal record, artifact manifest) stay with the in-kernel fixed-seed `[P-fuzz]`. Their decoders read constant offsets and clamp lengths.

```
  ok   policy: Done 4123749 runs
  ok   wan_cfg: Done 8916570 runs
  ok   frame_facts: Done 31191489 runs
  ok   glom: Done 27379792 runs
  ok   abslot: Done 29862048 runs
  ok   payload_header: Done 1625553 runs
  ok   http_req: Done 6240099 runs
  ok   dns_wire: Done 20582424 runs
  ok   tls_hello: Done 10121668 runs
  ok   frame_meta: Done 32999807 runs
FUZZ: PASS (300s per target)
```

## A9 — owner-journal replay (2026-11-12)

`tools/fuzz/heqk-kernel` target `owner_journal` compiles `ownerjournal.rs` (with `rpmb.rs` and `alerthook.rs`, the
types and record decoder its replay calls) from the device sources. `src/devpolicy.rs` is a host stand-in used only
so the journal's self-test compiles; the self-test is not run.

- Mode 0, raw sectors (someone with the card in a reader): the MAC gate refuses; no rule is applied without a valid
  chain (asserted).
- Mode 1, a valid MAC chain over fuzzed record bodies (the harness holds the unit key, as the kernel does): every
  kind / op / length / target / reason reaches `apply` and the alert-hook decoder.
- After each replay: accessors do not panic, the rule / artifact / label tables stay bounded, a second replay of the
  same bytes gives the same state, and an accepted append on top survives the next replay.

The form bodies of the upload and owner endpoints are covered by `http_req` (`form_get` over the same keys).
Replaces the in-kernel fixed-seed `[P-fuzz]` as the coverage-guided check for the journal record decoder.

```
  ok   owner_journal: Done 1129642 runs (300 s, 0 crashes, cov 426)
```
