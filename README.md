# HookProbe OS

> **One operating system. Every platform. Hardware only unlocks capabilities.**
>
> *HookProbe OS is the operating system. SOC is its default workspace. Hardware only unlocks capabilities.*

HookProbe OS is a security operating system built on **heqk**, our own Rust capability microkernel.
The device runs **no Linux at all**. heqk is the network sensor, the IPS and the Mission Control
web server. A full SOC runs on a Raspberry Pi CM5 board, standalone and air-gap capable,
with no account needed. A cloud control plane is optional and adds features on top.

This repository is **one project** that you can follow from top to bottom:

```
                    IMAGE BUILD ENGINE                      os/build/
                           |
                PLATFORM-SPECIFIC PROFILES                  appliance/
                  /                   \
            CM5 TARGET             QEMU TARGET              appliance/cm5/ · os/kernel (QEMU virt)
                |                      |
          Signed boot             Signed image              os/build/ (hboot: Ed25519 + SLH-DSA)
          components              + manifest
                |                      |
          WebUSB / USB            Download image            tools/flash/ · os/provisioning/
          provisioning            raw / qcow2
                |                      |
          Hardware ID             Virtual ID                os/device-identity/ · onboarding/enrollment/
          and trust               and enrollment
                  \                   /
                   HOOKPROBE CONTROL                        onboarding/enrollment/ (off-device control plane)
                           |
               Distributed Security Intelligence
```

## Start here

| I want to… | Go to |
|---|---|
| Understand what HookProbe OS is | [`docs/architecture/`](docs/architecture/) |
| Build and test it in QEMU (no hardware) | [`docs/getting-started/`](docs/getting-started/) |
| Build a signed CM5 image | [`os/build/`](os/build/) |
| Flash a CM5 | [`tools/flash/`](tools/flash/) |
| Find a driver / the network stack / the security code | [`os/`](os/) |
| See supported hardware | [`appliance/`](appliance/) |
| First boot, Wi-Fi, enrollment, setup UI | [`onboarding/`](onboarding/) |
| Read the decisions (ADRs) and the roadmap | [`docs/adr/`](docs/adr/) · [`docs/roadmap/`](docs/roadmap/) |
| Find the previous HookProbe (V1 Python, V2 Linux tier) | [`legacy/`](legacy/) |

## Repository map

| Folder | What lives there |
|---|---|
| [`os/`](os/) | The device OS: the heqk kernel workspace, Mission Control UI, the image build engine, plus indexes for drivers, networking, security, identity and provisioning |
| [`appliance/`](appliance/) | Hardware profiles: CM5, Waveshare dual-Ethernet carrier |
| [`onboarding/`](onboarding/) | First-boot and registration: Wi-Fi, enrollment, setup UI |
| [`docs/`](docs/) | Architecture, getting-started, security, roadmap, ADRs, design records |
| [`tools/`](tools/) | Developer tools: build helpers, flashing, diagnostics |
| [`legacy/`](legacy/) | `v1/`: the original HookProbe (Python/Zig, Fortress/Guardian/Nexus/Sentinel). `linux-tier/`: the V2 bootc/Debian tier (bug and security fixes only, ADR 0047) |

## Status (honest)

- **CM5 metal:** the zero-Linux factory image passed full acceptance on 2026-11-04. heqk boots,
  detects and drops an attack, and shows it in Mission Control in a browser.
- **QEMU:** `os/kernel/validate.sh` boots every phase gate, and `os/kernel/tools/mc-e2e.sh` runs
  the browser end-to-end check.
- **Not built yet:** the WebUSB browser flasher, raw/qcow2 image downloads, and virtual-device
  identity/enrollment for QEMU and VMs.
  Other platforms (RK3588, N100, cloud) are planned on heqk (ADR 0047).

## License

Dual-licensed: **AGPL-3.0** + commercial. See [`LICENSE`](LICENSE) and [`LICENSING.md`](LICENSING.md).
Security issues: [`SECURITY.md`](SECURITY.md). Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md).
