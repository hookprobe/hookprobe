# heqk "house" metal test plan — change settings live, survive reboot, revert (2026-11-12)

Goal (operator): once inside the house, settings change without leaving it. Prove on the dev CM5 that the owner can change
settings and the Wi-Fi password **live**, that every change **survives a reboot** (sealed at rest), that stations
**connect / disconnect / reconnect** with the new password, and that the device returns to the **original setup**
afterwards — then the metal batch continues.

Scope note: the owner path under test is Mission Control's authenticated session → signed HQCFG1 bundle upload →
cfgd live apply → sealed store. The EL0 management shell (el0-hsh) is not in the release image yet (its transport
`hsh-dev` is development-only), so it is not part of this plan.

Script: `tools/diagnostics/cm5-house-check.sh <owner-key> <serial-log> <config-key>` (needs `PI_SUDO_FILE`).

## Safety

- The bench Pi is controlled over eth0 (fortress LAN), so losing its Wi-Fi never loses control.
- Mission Control is also reachable on the management VLAN (192.168.200.146); the owner confirm always goes that way.
- Every Wi-Fi change waits for the confirm (300 s), else it reverts live by itself.
- Passphrases: the original is read from the Pi's saved profile; the test passphrase is random. Both stay in a 0700
  temp dir, are never printed, and are shredded at the end (bundles included).

## Phases

| # | Step | Pass criteria |
|---|---|---|
| 0 | **Baseline.** Record `/api/config` (generation, state, at_rest), the Pi's saved AP profile, the policy behaviour (DNS to 9.9.9.9 dropped by `policy-bench`). | MC answers on mgmt and on the AP; baseline recorded |
| 1 | **Change settings live.** Bundle A = bench WAN as **static** 10.100.0.200/24 + a policy that allows DNS to 9.9.9.9. | Reply `applies:"live"`, `reboot_required:false`; serial `[WAN] live apply: mode STATIC`, `[POLICY] live apply: swapped in`; DNS 9.9.9.9 now answers; owner confirm commits |
| 2 | **Reboot → kept.** | Serial `generation A in force (committed)`; `/api/config` generation A, sealed at rest; WAN static; DNS 9.9.9.9 still answers |
| 3 | **Change the Wi-Fi password live.** Bundle B = A + Wi-Fi (same SSID, random passphrase, WPA3 transition). | `applies:"live"`, `needs_confirm:true`; serial `[WIFI] live apply … BSS re-started` |
| 4 | **Connect with the new password**, then confirm. | Pi joins with the new passphrase (temporary profile), gets a 10.99.0.x lease, MC answers on the AP; the **old** profile is refused; confirm commits B |
| 5 | **Disconnect / reconnect** ×3 with the new password. | Every reconnect: associated + lease + MC within 60 s; no firmware halt |
| 6 | **Reboot → kept.** | Generation B committed after boot; the Pi re-joins with the **new** passphrase; the old one is still refused; at_rest sealed |
| 7 | **Revert to the original setup.** Bundle C = the bench's original WAN file + `policy-bench` + the original Wi-Fi (SSID / passphrase from the Pi profile). | `applies:"live"`; the Pi's original saved profile reconnects; confirm commits C; DNS 9.9.9.9 dropped again |
| 8 | **Reboot → original kept.** | Generation C committed; the Pi joins on its original profile; the test passphrase is refused; WAN = bench DHCP (VLAN 100) + mgmt DHCP (VLAN 200) |
| 9 | **Continue.** The batch proceeds (live-apply revert check, Wi-Fi spike, WPA3, LAN client). | — |

Rule 7 is checked after every step: Mission Control answers on the management VLAN, and on the AP whenever a
station is joined with the current passphrase.

Note on "original": the factory baseline is the per-file WAN.TXT / POLICY.TXT / WIFI default. A bundle that carries
the same content is functionally identical; the device does not return to "no bundle" (an owner rollback goes to the
previous verified generation, by design).

## Evidence

`$R/house.log` (each step `ok` / `BAD`), the serial log excerpt, `/api/config` before and after each reboot. A step
that fails stops the Wi-Fi part (phases 3–6) but always runs phase 7–8, so the bench returns to the original setup.

## Shell command validation (bench image with `hsh-dev`)

The management shell (el0-hsh) answers over a development transport (`POST /api/hsh`) that only a bench image
built with `hsh-dev` carries (release builds refuse the feature). A second bench image, identical except for
`hsh-dev`, runs `tools/diagnostics/cm5-hsh-check.sh`:

| Group | Checks |
|---|---|
| Transport | no owner session → refused; foreign Origin → 403 |
| Read-only (role view) | `help`, `version`, `info`, `uptime`, `wan status`, `interface show wan`, `qsecbit status`, `config status`, `owner status`, `security posture` answer from the EL0 shell with live state (uptime advances) |
| Refusals | `config confirm` / `config rollback` refused without owner elevation (role operate); unknown command; a spec command not in this build; malformed `config stage` / `owner elevate` arguments |
| Robustness | an oversized line and binary bytes: the shell keeps answering |
| Consistency | `config status` = `/api/config` generation; a live policy change is visible in the shell without a reboot; after a reboot shell and API agree on the kept generation; `owner status` shows fingerprints only |

Batch order: **MB1** (release-equivalent image `imgM2`): flash → live-apply check → Wi-Fi live spike → WPA3 → LAN
client. **MB2** (`imgM2s` = `imgM2` + `hsh-dev`): flash → shell check → the house check above (it ends on the
original setup) → back to building (the 72 h soak is deferred by the operator, 2026-11-12).
