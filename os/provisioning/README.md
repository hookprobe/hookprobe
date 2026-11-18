# os/provisioning — getting a signed image onto a device (index)

| Step | Where |
|---|---|
| Build the signed factory disk image | [`../build/make-cm5-heqk-disk.sh`](../build/make-cm5-heqk-disk.sh) |
| Flash a CM5 over USB (rpiboot) | [`../../tools/flash/`](../../tools/flash/) → `../kernel/cm5-boot/flash-image.sh` |
| A/B slots + tryboot update / rollback | [`ota.rs`](../kernel/kernel/src/ota.rs), [`abboot.rs`](../kernel/kernel/src/abboot.rs), [`../kernel/cm5-boot/ab-update.sh`](../kernel/cm5-boot/ab-update.sh) |
| Mission Control TLS chain for a device | [`../kernel/tools/mctls-provision.py`](../kernel/tools/mctls-provision.py) |
| Per-unit factory provisioning station (identity, setup credential, owner key, TLS cert, label, self-test, record) | [`../../tools/provisioning/`](../../tools/provisioning/README.md) |
| Signed operator policy | [`../kernel/tools/policy-sign.py`](../kernel/tools/policy-sign.py) |

Decisions: ADR 0054 (per-device setup credential), ADR 0058 and ADR 0059 D10 (owner-signed configuration,
owner key and recovery), ADR 0051 (owner CA). ADR 0037 (zero-touch onboarding / flasher) was retired on
2026-11-12 and is kept as a historical record; it is still the only design for the browser flasher.
**Not built yet:** the WebUSB browser flasher and raw/qcow2 downloads for the QEMU target.
