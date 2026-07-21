# HEQK Core — Security Audit & Fixes (2026-07-20)

A deep vulnerability audit of the kernel source (a parallel adversarial review of every file, plus targeted fixes). Five findings; four fixed, one partially mitigated with the full fix deferred to a named larger effort. Each fix is validated (`./validate.sh` green, P0–P6b + DRV).

| # | Sev | Defect | Disposition |
|---|---|---|---|
| 1 | **HIGH** | **virtio RX: device-controlled `id`/`len` used to index buffers unchecked** (`virtio.rs`) — a hostile/buggy NIC sets `id` huge → OOB read of kernel RAM into the packet buffer (info-leak) or a data abort. | **FIXED** — `if id >= QSZ \|\| len <= NET_HDR \|\| len > BUF_SZ { return None }` before use. Untrusted device input is now bounded. |
| 2 | **HIGH** | **User pages had no UXN/PXN** (`mmu.rs`) — the EL0 **stack was executable** (classic exec-stack → shellcode), and every EL0-writable page was **executable at EL1** (priv-esc if the kernel ever branches into user memory). | **FIXED** — split into `map_user_code_page` (EL0 RO+exec, **W^X**), `map_user_data_page` (EL0 RW, **UXN+PXN**), `map_user_device_page` (Device, UXN+PXN). Kernel data pages get UXN+PXN too. |
| 3 | MED | **JIT "W^X" defeated by a writable identity alias; GB1 RAM is RWX at EL1** (`bpf_jit.rs`/`mmu.rs`) — JIT code is RO+exec at its VA but still **writable via its identity mapping**; and the 1 GiB kernel RAM block has no PXN, so heap/stacks/JIT frames are executable at EL1. | **PARTIALLY MITIGATED / DEFERRED** — JIT code is RO+exec via its exec alias and EL0-non-exec; user/kernel *data* pages now carry PXN. The full fix (remove the RW identity alias of code frames + PXN kernel *data* while keeping kernel *text* executable) requires **kernel-page block-splitting** — the already-named deferred W^X gap (`buildPlan.md`). Documented, not hidden. |
| 4 | MED | **Unexpected EL1 (kernel) fault exited with code 0 (success)** (`exception.rs`) — a real kernel crash (e.g. from #1) terminated QEMU with status 0, which the harness read as PASS, laundering crashes into "green." | **FIXED** — `rust_exception` now `exit(1)`; only the deliberate all-tests-passed path exits 0. Kernel crashes can no longer masquerade as success. |
| 5 | LOW | **`verify()` off-by-one and not enforced** (`bpf.rs`) — accepted a jump to `== prog.len()`; and `verify()` gated nothing (only a self-test), so a future third-party BPF path would be fail-open. | **FIXED** — bound corrected to `>= prog.len()`; the signed threat rule is now **verified before the datapath runs it** (verify-then-run), establishing the discipline for future untrusted rules. |

## Confirmed sound (audited, no change needed)
- BPF interpreter runtime checks — LDX bounds, register-index (`>= 11`), and step-limit (termination) are correct; `wrapping_*` prevents overflow UB.
- Syscall boundary dereferences **no** EL0-supplied pointer; `SYS_CAP_IDENTIFY`'s CPtr goes through bounds-checked `slots.get()`.
- `caps::revoke` recursion is bounded by the CNode slot count.
- Kernel RAM identity map is correctly `AP_RW_EL1` (EL0 no-access); IPC critical sections mask IRQs; the trap-frame save/restore is symmetric.

## The one honest residual
**Full W^X for kernel code and the JIT (#3) needs kernel-page block-splitting** — replacing the coarse 1 GiB identity blocks with per-page mappings so kernel *text* is RX, kernel *data* is RW+PXN, and JIT frames have no writable alias. That is the same deferred item that also blocks per-address-space ASIDs, tracked in `buildPlan.md`. It is a real limitation, not a claimed-green gate.

*Method: adversarial source review of all of `kernel/src` + `arch-aarch64/src`, ranked by exploitability, each fix re-validated against the full P0–P6b + DRV gate ladder.*
