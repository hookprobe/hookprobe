# ADR 0010 — Zero-touch provisioning: the captive portal that becomes Mission Control

**Status:** ✅ Accepted (2026-07-02). **⚠️ Decision accepted; the PORTAL front-door is ⬜ NOT BUILT (~0%).** The reconciler *engine* it reuses exists (`hookprobe-network-reconcile`, `WanIntent`/`LanIntent`, plan-as-diff apply&verify), but the captive-portal service, `setup.hookprobe.local`, the `provision/status` endpoint, and the USB signed-ignition front-door do **not** exist yet — the headless first-boot differentiator is unbuilt. Fulfils the deferred **E4 setup wizard** of ADR 0007 and the
"zero-touch first boot" sketch there. Builds directly on machinery already validated on hardware:
the SASE-edge built-in AP, the deterministic **intent → plan-as-diff → apply & verify** reconciler,
and the self-detecting encryption **anchor tiers** (ADR 0007 E3). No new subsystem — a UI over the
engine that already exists.

## Context

A headless appliance has to bridge the gap between the user's intent and the OS with no keyboard,
monitor, or serial console. Three transports were considered: a **USB "ignition" file**, **BLE
proximity** (phone app), and a **Wi-Fi captive portal**. What's already true on the device shapes the
answer:

- The edge already brings up a Wi-Fi AP (`HookProbe`) at first boot (SASE default, validated).
- Config is never hand-written — the operator declares **intent**; AEGIS reconciles it as a diff and
  verifies. The "apply my setup" step is therefore *one reconcile pass*, not a bespoke script.
- The encryption anchor already self-detects (`software`/`tpm`/`passphrase`/`tang`) — setup only has
  to *offer to flip the tier*, not implement crypto.
- Live finding (2026-07-02): the AP comes up ~10 s **before** the WAN uplink gets its DHCP lease, so a
  client that associates during boot briefly has "connected, no internet." The handoff must model WAN
  readiness explicitly.

## Decision 1 — Captive portal is the default; signed USB ignition is the pro/fleet path; BLE is deferred

| Transport | Feasible now | Role |
|---|---|---|
| **Captive portal** | ✅ uses the existing AP, **no app**, any browser, rides OS captive-portal detection | **Default** — lowest adoption friction, zero added hardware |
| **USB `ignition.hp`** | ✅ a service that verifies a **signed** intent file and feeds the reconciler | **Fleet / air-gap / remote-worker** — same engine, offline front door |
| **BLE proximity** | ❌ needs native iOS+Android apps; Pi-class BT is fragile (observed `hci0` init failure) | **Deferred** until a mobile app + reliable BT justify it |

All three are just **transports for the same intent object into the same reconciler**. Front doors are
pluggable; the engine is one.

## Decision 2 — The portal captures *intent*, not config

"Launch SASE" does **not** poke `nft`/eBPF maps. It writes an intent (`network.yaml` = `WanIntent` +
`LanIntent` + anchor choice) and triggers `hookprobe-network-reconcile` — the exact service validated
on hardware. The user is shown the change as a **human-readable plan-as-diff** *before* committing;
the reconciler applies **and verifies** it, so it is rollback-able. This is the unique differentiator:
setup is a previewed, verified state transition, not a form that reboots and hopes.

## Decision 3 — The seamless handoff (the "booster drop"): keep L2 stable, flip L3

Destroying the setup SSID and broadcasting a different production SSID **drops the user's session** and
they never see the redirect. Instead the reconcile keeps L2 identical and flips only routing/DNS:

| | Setup phase | After "Launch" (same reconcile) |
|---|---|---|
| AP SSID / BSSID | `HookProbe` | `HookProbe` — *unchanged* |
| LAN gateway IP | `10.66.0.1` | `10.66.0.1` — *unchanged* |
| DNS (resolved) | wildcard → portal (captive) | real resolver / DoH |
| WAN + NAT + mesh | down; client isolated, no pivot | up (SASE default) |
| Client DHCP lease | valid | *same lease, still valid* |

The client never disassociates and its IP never changes, so the portal's JS keeps polling
`GET http://10.66.0.1/api/provision/status` across the whole teardown. It advances only on
**WAN-readiness** (`ip route show default dev <wan>` exists) — turning the observed ~10 s AP-before-WAN
window into a "watch it come online" progress bar instead of dead air. On `state:"live"` it redirects
to `https://os.hookprobe.local` (mDNS via `avahi`), with a **stable `https://10.66.0.1` fallback** for
clients where `.local`/Bonjour is flaky. Honest caveat: `.local` HTTPS trust — the first screen offers
to install a device-identity-anchored local CA (ties to the TPM/software-PUF identity that exists
before any account).

## Decision 4 — Progressive disclosure: AI-conversational, newbie-first

Setup is driven by the copilot (the "AI is the interaction layer" principle), which yields progressive
disclosure for free:

- **Default (newbie, ~3 taps):** *"I see link on eth0 already pulling a DHCP lease — use it as your
  internet? [Yes] · [It's PPPoE] · [Advanced]"* → set Wi-Fi name/password → **Launch**.
- **"Advanced" reveals** only what the manifest grants: PPPoE creds, VLANs, dual-WAN failover, DoH,
  mesh peers — the full `WanIntent`/`LanIntent` schema. Power users opt *in*; newbies never see it.

## Decision 5 — The portal is permanent "easy mode", and it closes E4

After Launch the same app persists at **`setup.hookprobe.local`** — no longer captive, just a web
service. In the one-system model it is **not a second app**: it is the **newbie lens of the
Network/Gateway workspace** (`MissionControl.md §6b`). Day-0 setup and day-300 ISP swaps use the same
tool at two disclosure levels. This flow **completes the deferred E4 items**: it *is* the setup wizard,
and the **passphrase enrollment** (E4c backend already done) is one optional screen inside it —
*"Protect your data with a passphrase? [Skip — factory key] · [Set one]"* — which flips the encryption
anchor from `software` to the `passphrase` tier.

## Decision 6 — Security & standalone

- **First-boot claim:** the first screen sets the local admin (RBAC, ADR 0008); until claimed, the
  portal accepts input only from the isolated setup AP (physical proximity = the auth).
- **Device-identity bound:** the committed intent (and any `ignition.hp`) is signed/verified against
  the device's anchor-bound key — the identity exists before any account.
- **Standalone by default:** the entire flow needs no cloud. Tenant linking (`mssp.hookprobe.com` or a
  self-hosted CP) is one optional last screen, never a precondition.
- **No pivot during setup:** the setup AP is client-isolated with the WAN blackholed until Launch.

## Consequences / phasing

- **Phase 1 (MVP, closes E4):** captive portal — AI-conversational intent capture + plan-as-diff +
  L2-stable handoff with WAN-readiness poll + passphrase enrollment. New: `hookprobe-setup-portal`
  service (`ConditionFirstBoot`/`!.setup-complete`), the portal web app, `avahi` (mDNS), a resolved
  captive drop-in the reconcile removes on Launch.
- **Phase 2:** signed USB `ignition.hp` (`hookprobe-usb-ignition.service`, `ConditionPathExists`) →
  same reconcile. Fleet/air-gap.
- **Phase 3 (maybe):** BLE, if a mobile app + reliable BT ever justify it.
- **Route to add to `MissionControl.md`:** Administration → Provisioning (first-boot claim, wizard) +
  the `setup.hookprobe.local` quick-config as the Network/Gateway newbie lens.

**The thesis:** the setup isn't a wizard you escape — it's the easy-mode you keep. Different because it
falls out of the intent-reconciler DNA (previewed, verified, seamless), not bolted on.

---

## Amendment (2026-07-17) — the "simple experience": value before configuration

**Status:** 🟡 Proposed (2026-07-17) — design-session posture pending operator ratification. Refines
(does not replace) Decisions 2/4/6 above with the "Apple of security" experience principles from a
design exploration. **Relates to:** [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md)
(the flasher-as-factory provisioning mechanics that precede this portal), [ADR 0040](0040-experience-ux-ui-scope-gui-features.md)
(the experience layer this is one instance of), [ADR 0035](0035-substrate-ownership-underlay-overlay.md),
[ADR 0023](0023-enforcement-separation.md) (the observe-first rule that makes the gateway step safe).

**Context.** ADR 0010 already made setup *intent-capture, not config*. This amendment goes one step
further on the *feel*: the industry default is configure-first, value-later; a security appliance can
invert it, because its detection is passive by construction. Simplicity fused with security — not fewer
features — is the moat.

- **A · Value BEFORE configuration.** The captive portal's first screen is **not** a form — it is the
  network *already mapped* with the *first finding* surfaced, because out-of-band detection is running
  the moment the device has link. You open the portal and it is already useful; configuration becomes
  optional refinement of a thing that already works, never a gate in front of it. (This sharpens
  Decision 4's newbie-first flow: the newbie's very first view is a result, not a question.)
- **B · Passive-first → promote-to-gateway is the shipped default.** The device starts **passive** the
  instant it is plugged in (instant value, *cannot* break the network); the user then **opts in** to
  promote it to a full inline gateway (WAN in / LAN out — the SASE default of Decision 3). "Never broke
  my internet" is how it earns the trust to *later* become the internet. Going inline is safe precisely
  because of the observe-first / fail-open / "a legitimate connection always passes" rule
  ([ADR 0023](0023-enforcement-separation.md)).
- **C · Three onboarding knobs, maximum.** WAN: DHCP / fixed / PPPoE / wireless-station-SSID · LAN:
  SSID. Everything else is a sane default. VPN-to-PoP, segmentation, and VLANs are **day-2**, revealed
  only under "Advanced" (Decision 4), never in the first-run flow.
- **D · Intent-driven, not a settings dump — with a pro escape hatch.** "What are you protecting?"
  generates the config (Decision 2's plan-as-diff); the classical `config interface / set / edit`
  vendor CLI grammar (importable, VyOS/Junos/Fortinet-familiar) is the **pro escape hatch underneath**,
  never the front door.
- **E · Hidden-Linux boot + logo, honest on failure.** First boot shows a HookProbe logo/splash with
  no kernel spew (Apple-style) — but it is **health-gated** (greenboot): never a green check on a
  broken box. Beautiful by default, honest on failure.

**Residual / honesty.** This is *feel*, layered on the same engine — it adds no new subsystem beyond
the portal already scoped in Consequences/Phase 1; the passive-first→gateway promotion is a new intent
state the reconciler must model (a lightweight extension of `WanIntent`, not a rewrite). Still ⬜: the
portal front-door itself remains unbuilt (see the top-of-file Status), so this amendment is posture for
*when* it is built, not a claim that it exists.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The captive-portal → intent → reconciler plan-as-diff flow is substrate-neutral; only the *apply* backend (nft/hostapd/DHCP/avahi) retargets to heqk's network stack. → **Phases M4/M5**.
