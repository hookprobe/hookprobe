# os/ — the HookProbe OS device image

Everything that runs **on the device**.

| Folder | What it is |
|---|---|
| [`kernel/`](kernel/) | **heqk**, the Rust aarch64 capability microkernel. One self-contained Cargo workspace (`kernel/`, `arch-aarch64/`, `hal/`, `hboot/`, `el0-*`, `tlsprov/`). Validate with `kernel/validate.sh`. |
| [`mission-control/`](mission-control/) | The Mission Control web UI (Astro + SolidJS). It is built to `dist/` and **embedded into the kernel** (`kernel/kernel/build.rs`), so heqk serves it from the device. |
| [`build/`](build/) | The image build engine: signed `heqk8.img` / `hboot` / factory disk images. |
| [`drivers/`](drivers/) | Index: hardware drivers (Ethernet, Wi-Fi/BT, eMMC, RP1 peripherals) and the Wi-Fi firmware blobs. |
| [`networking/`](networking/) | Index: packet path, IPS verdict, NAT/uplink, IPv6, PPPoE, DNS, segmentation. |
| [`security/`](security/) | Index: capabilities, measured boot, sealed storage, BPF threat plane, TLS. |
| [`device-identity/`](device-identity/) | Index: the hardware-derived device key, attestation, the owner key. |
| [`provisioning/`](provisioning/) | Index: factory image, flashing, A/B OTA, signed policy. |

> **Why are drivers/networking/security index pages and not code folders?** heqk is one Rust
> workspace. A driver is a module of `arch-aarch64`, not a separate crate. Splitting the files across
> folders would break the build and their history, so each folder here lists where the code lives.
