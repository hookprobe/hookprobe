# onboarding/enrollment — joining a control plane (optional)

A device enrolls over a **PQ-hybrid Noise** channel (ML-KEM + X25519). Each side authenticates the
other: the device signs with its SRK-derived Ed25519 identity, and the control plane is pinned by a
key baked into the image. Once enrolled, the device can export evidence and receive signed reach
policy. Without enrollment it keeps running as a full local SOC.

| What | Where |
|---|---|
| Device side | [`enroll.rs`](../../os/kernel/kernel/src/enroll.rs), [`securechannel.rs`](../../os/kernel/kernel/src/securechannel.rs), [`controlplane.rs`](../../os/kernel/kernel/src/controlplane.rs), [`exportwire.rs`](../../os/kernel/kernel/src/exportwire.rs) |
| **Control-plane responder** (host) | [`responder-sim/`](responder-sim/): it links the kernel's own `securechannel.rs`, so the wire bytes are identical |
| Design | [heqk-control-plane](../../docs/design/heqk-control-plane.md) |

```sh
cd onboarding/enrollment/responder-sim
cargo run --release -- --selftest                                   # no hardware
cargo run --release -- --live --dev-pk <pk printed at boot> --evidence-out ev.jsonl
```
