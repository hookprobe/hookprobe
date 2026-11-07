# ADR 0037 — Zero-touch onboarding & the flasher-as-factory provisioning root

**Status:** 🟡 Proposed (2026-07-17) — design-session posture, pending ratification. **Extends [ADR 0010](0010-zero-touch-provisioning.md)** *upstream* (the provisioning root that precedes first boot) and *forward* (the passive-first posture and value-before-config screen). Honest split: **implemented today** — standalone/no-account default, publickey-only release images (no user, root locked), the SASE built-in AP, the intent→plan-as-diff reconciler, `make-pi-image.sh`/`hookprobe-flash.sh` factory tooling, device identity (TPM-bound or software) minted before any account. **Vision (⬜ not built)** — the browser flasher, the passive→gateway promotion flow, the "already watching" first screen, per-device setup-AP keys born at flash, hidden-Linux splash.
**Deciders:** ux-architect (author), os-architect, security-auditor, release-engineer.
**Relates to:** [ADR 0010](0010-zero-touch-provisioning.md) (the captive portal that becomes Mission Control — 0037 does **not** re-derive its portal/handoff mechanics), [ADR 0019](0019-bootc-debian-substrate.md) (the image this provisions), [ADR 0035](0035-substrate-ownership-underlay-overlay.md) (underlay/overlay — passive is the underlay observing; gateway is inline), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (the signed image the flasher writes; the device self-verifies it on boot), [ADR 0023](0023-enforcement-separation.md) (observe-first/fail-open — what makes inline safe), [ADR 0008](0008-rbac-admin-operator.md) (first-boot claim → local admin).

---

## Context

ADR 0010 solved *first-boot intent capture* (a captive portal over the built-in AP that becomes Mission Control). Two gaps sit around it, and both are decided here:

1. **Upstream of first boot** there is no factory. HookProbe is open-source, DIY-flashed hardware — there is no assembly line to print a per-device sticker or provision a key. Yet a security appliance must NOT ship a shared default credential (the single most common appliance-CVE class is *unauthenticated first boot / default creds* — fatal for a security product specifically). Something has to be the provisioning root.
2. **The first-boot posture** in 0010 assumes the device comes up as an inline SASE gateway. But an inline box is in the customer's critical path from second zero — the fastest way to lose trust is to break their internet on day one.

The resolution to both is a reframe: **the flash is the provisioning moment, and the OS earns the right to be inline before it takes it.**

## Decision 1 — The flasher IS the factory

Provisioning happens at **flash**, on the owner's own machine — whoever writes the image is holding the device. A **branded, static, client-side browser flasher** (the ESP-Web-Tools / WebSerial+WebUSB model) is the front door:

- User **picks their platform** → the flasher fetches the correct **pre-built, signed image** ([ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md)). Users **personalize, never build** — the per-platform image matrix differs only by kernel/boot/DTB because everything above the base is capability-gated "one system" ([ADR 0035](0035-substrate-ownership-underlay-overlay.md)).
- In-browser (nothing hits a server): generate a **random per-device setup-AP WPA key**, and **mint the owner claim credential** which is bound into the image. The device **self-mints its own identity keypair on first boot** (software-sealed — the Pi has no TPM); the browser only establishes *owner→device* binding and **never holds the device private key**.
- **Platform reality (honest):** a Pi boots from storage, not serial. **CM5/CM4** are genuinely browser-flashable via **WebUSB + rpiboot** (eMMC as USB mass storage). **SD-based Pi4/5** need a helper (`rpi-imager` pointed at a HookProbe repo) because browsers cannot reliably raw-write an SD; the browser still owns the *personalize/provision* step, only the raw write is handed off.

**Flash-time keys beat factory stickers on security:** a printed default key exists in a warehouse and leaks in bulk; a flash-time key **only ever existed on the owner's machine** — never in a factory, a database, or on a label. The open-source constraint yields a *better* provisioning story than the incumbents.

## Decision 2 — Distribution is GitHub; "no backend" is a security property

Repo (open) · **Actions** builds the small signed per-platform image matrix · **Releases** hosts the signed artifacts · **Pages** hosts the static flasher. The flasher is 100% client-side, so **no server ever touches a key or an identity** — a property to advertise, not merely a convenience: *"there is no backend; we couldn't exfiltrate your keys if we wanted to."* No in-browser signature verification is needed because the **device verifies its own image on boot** (trust store, [ADR 0016](0016-artifact-hash-signing.md)). Browser flashes; silicon checks.

## Decision 3 — Physical possession is the only credential

No default password, ever. HTTPS with a device-identity-rooted cert (the local-CA offer of ADR 0010 D3). The isolated **setup AP uses the per-device WPA key** born at flash (D1) — so "connect to the setup network" already proves possession, closing the *anyone-in-Wi-Fi-range races to claim* window that an open setup AP leaves. First-boot claim sets the local admin (ADR 0008 / ADR 0010 D6). Standalone/no-account throughout; cloud/tenant enrollment stays optional and additive, never a precondition — device identity exists before any account.

## Decision 4 — Passive-first → promote-to-gateway (the shipped default)

The device starts **passive** the instant it is plugged into a LAN — observing out-of-band, unable to break anything (it *is* the underlay watching, [ADR 0035](0035-substrate-ownership-underlay-overlay.md)). The user **opts in** to promote it to a full inline gateway (WAN in / LAN out), via the ADR 0010 reconcile. Rationale: *"never broke my internet"* is what earns the trust to later *become* the internet. And inline is **safe when they promote** precisely because of the observe-first / fail-open / "a legitimate connection always passes" rule ([ADR 0023](0023-enforcement-separation.md)) — the hard enforcement-separation rule is exactly what lets this onboarding offer inline mode without risking the customer's uplink.

## Decision 5 — Value before configuration; hidden-Linux boot; honest on failure

- **Value first:** because detection is passive by default, the first screen shows **"I'm already watching — here is your network, mapped, and the first thing I noticed"**, *not* a config form. Everyone else gates value behind configuration; HookProbe inverts it — configuration becomes optional refinement of something already useful.
- **Hidden Linux:** logo + splash, no kernel spew (Apple-style) — but health-gated by greenboot: **never a green check on a broken box.** A failed health gate or a WAN that never came up says so plainly.
- **Guided intent, not a settings dump:** the flow asks *"what are you protecting?"* and generates config (the AI-conversational disclosure of ADR 0010 D4). **Three onboarding knobs maximum** — WAN (DHCP / fixed / PPPoE / wireless-SSID) and LAN (SSID); VPN-to-PoP, VLANs, and segmentation are day-2, never first-run. The classical `config interface / edit / set / next` grammar (importable, VyOS/Junos/Fortinet-like, so operators feel at home) is the **pro escape hatch underneath**, never the front door.

## Decision 6 — Discovery must never dead-end

Three on-ramps, because mDNS alone is fragile (no cross-subnet/VLAN, often enterprise-blocked):

1. **`hookprobe-<short-id>.local`** — mDNS/Bonjour, per-device short id so a fleet never collides on one name.
2. **First-boot setup AP / captive portal** — the device already has AP capability, which kills the chicken-and-egg of *needing a network to configure the thing that manages the network* (ADR 0010 D1/D3 handoff applies unchanged once promoted).
3. **QR on the monitor** if one is attached — deep-links a phone straight into setup.

## Consequences

- **+** One coherent trust story: the flasher provisions, the owner is the only party who ever saw the key, the device self-verifies its image and self-mints its identity, and nothing crosses a server. This composes with [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) into an end-to-end *verify-don't-trust* chain with no trusted third party.
- **+** Passive-first makes the risky part (inline) *opt-in after* trust is earned, and ADR 0023 is what makes the opt-in safe — the onboarding leans on decisions already made.
- **−** The browser flasher is net-new and platform-uneven (WebUSB/CM5 direct; SD-Pi helper-assisted); the "already watching" first screen depends on the passive observation + finding pipeline being fast and legible on first boot.
- **−** Per-device-key-at-flash requires the flasher/`hookprobe-flash` tooling to become genuinely security-critical (it mints the owner credential); it must itself be reproducible and signed (ADR 0036), or the provisioning root becomes the weak link.
- **Route to add to `MissionControl.md`:** Administration → Provisioning gains the *flasher* (pre-first-boot) and the *passive→gateway promotion* toggle; the "already watching" view is the Observe workspace surfaced at first boot.

**The thesis:** the factory you don't have is the flash you do; the device earns the wire before it sits on it; and the very first thing the operator sees is a finding, not a form.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The browser-flasher, per-device-key provisioning, passive-first→promote flow is substrate-agnostic; the flasher writes a `heqk8.img` instead of the Linux image, and "device self-verifies image on boot" is already **realized** by heqk's attested `hboot` (OTP-rooted, hybrid-PQC, anti-rollback). → **Phases M1/M4**.
