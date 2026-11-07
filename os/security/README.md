# os/security — on-device security (index)

| Area | Source | Design |
|---|---|---|
| Capabilities (CSpace, revoke) | [`caps.rs`](../kernel/kernel/src/caps.rs) | [CAPABILITY_MODEL.md](../kernel/CAPABILITY_MODEL.md), [PER_TCB_CSPACE.md](../kernel/PER_TCB_CSPACE.md) |
| Measured, signed boot + anti-rollback (hboot) | [`hboot/src/`](../kernel/hboot/src/) | [heqk-signing-identity](../../docs/design/heqk-signing-identity.md) |
| Sealed storage | [`seal.rs`](../kernel/kernel/src/seal.rs), [`store.rs`](../kernel/kernel/src/store.rs) | [SEALED_STORAGE.md](../kernel/SEALED_STORAGE.md) |
| BPF threat plane (RFC 9669) + rules | [`bpf.rs`](../kernel/kernel/src/bpf.rs), [`bpf_jit.rs`](../kernel/arch-aarch64/src/bpf_jit.rs), [`rules.rs`](../kernel/kernel/src/rules.rs), [`rulecat.rs`](../kernel/kernel/src/rulecat.rs) | [BPF_THREAT_PLANE.md](../kernel/BPF_THREAT_PLANE.md) |
| Wasm detection host (wasmi at EL0) | [`el0-wasmhost/`](../kernel/el0-wasmhost/), [`wasmhost.rs`](../kernel/kernel/src/wasmhost.rs) | [heqk-module-runtime](../../docs/design/heqk-module-runtime.md) |
| Secure channel (Noise, PQ-hybrid) | [`securechannel.rs`](../kernel/kernel/src/securechannel.rs) | |
| Mission Control HTTPS + sign-in | [`tlshost.rs`](../kernel/kernel/src/tlshost.rs), [`el0-tlshost/`](../kernel/el0-tlshost/), [`mcauth.rs`](../kernel/kernel/src/mcauth.rs) | ADR 0051 |
| Signed operator policy | [`policysig.rs`](../kernel/kernel/src/policysig.rs) | |

Audits: [SECURITY_AUDIT.md](../kernel/SECURITY_AUDIT.md). Project-wide policy: [`docs/security/`](../../docs/security/).
