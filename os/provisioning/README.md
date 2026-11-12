# os/provisioning — getting a signed image onto a device (index)

| Step | Where |
|---|---|
| Build the signed factory disk image | [`../build/make-cm5-heqk-disk.sh`](../build/make-cm5-heqk-disk.sh) |
| Flash a CM5 over USB (rpiboot) | [`../../tools/flash/`](../../tools/flash/) → `../kernel/cm5-boot/flash-image.sh` |
| A/B slots + tryboot update / rollback | [`ota.rs`](../kernel/kernel/src/ota.rs), [`abboot.rs`](../kernel/kernel/src/abboot.rs), [`../kernel/cm5-boot/ab-update.sh`](../kernel/cm5-boot/ab-update.sh) |
| Mission Control TLS chain for a device | [`../kernel/tools/mctls-provision.py`](../kernel/tools/mctls-provision.py) |
| Per-unit factory provisioning station (identity, setup credential, owner key, TLS cert, label, self-test, record) | [`../../tools/provisioning/`](../../tools/provisioning/README.md) |
| Signed operator policy | [`../kernel/tools/policy-sign.py`](../kernel/tools/policy-sign.py) |

Decision: ADR 0037 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059) (zero-touch onboarding / flasher).
**Not built yet:** the WebUSB browser flasher and raw/qcow2 downloads for the QEMU target.
