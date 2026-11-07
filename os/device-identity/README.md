# os/device-identity — hardware ID and trust (index)

On a CM5 the device identity comes from hardware. An Ed25519 key is derived from the OTP-fused
**SRK** as `HKDF(SRK, "HEQK-DEVICE-IDENTITY-ed25519-v1")` and printed at boot as `[NETCP] pk=`.
The EL1 kernel can never read the OTP itself. An EL2 proxy blocks that access (SEC-2).

| Area | Source |
|---|---|
| Key derivation + attestation key | [`ak_derive.rs`](../kernel/hboot/src/ak_derive.rs), [`attest.rs`](../kernel/hboot/src/attest.rs), [`measure.rs`](../kernel/hboot/src/measure.rs) |
| Attestation service | [`attest_svc.rs`](../kernel/kernel/src/attest_svc.rs) |
| Enrollment to a control plane | [`enroll.rs`](../kernel/kernel/src/enroll.rs) (see [`onboarding/enrollment`](../../onboarding/enrollment/)) |
| Owner key (factory image, `.owner-key`) | [`../build/make-cm5-heqk-disk.sh`](../build/make-cm5-heqk-disk.sh) `--owner-token` |

Design: [heqk-signing-identity](../../docs/design/heqk-signing-identity.md), ADR 0046.

**Not built yet: virtual identity** for the QEMU/VM target (no OTP to derive from). This is an
open design item.
