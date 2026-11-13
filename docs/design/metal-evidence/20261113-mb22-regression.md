# Metal evidence — MB22, 2026-11-13 12:05–12:40 (CM5): consolidated regression on main, one image — all green

Sprint E style: every metal check in one batch on ONE image, hashes recorded.

| Item | Value |
|---|---|
| Source | main `f22bf904` (incl. #1108 `/api/system`, #1119 artstore fallback fix) |
| Build id | `m22-f22bf904`, shipping AP features (`hboot,apmc,wifi-bigtx,appersist,wpa3`) |
| `heqk8.img` | 5,160,624 B, sha256 `3094bba5057965d9…` |
| `disk.img` | sha256 `a95edc58d3ee3434…` |
| Wi-Fi firmware | `cyw43455-sdio.bin` sha256 `d608f866582519c0…` (REL-08 PMKID correction on with `wpa3`) |
| Flash | runbook, one attempt; build id confirmed on serial; known-good restored after (RESTORE RC=0) |

| Check | Result |
|---|---|
| `GET /api/system` | build `m22-f22bf904`, slot A, trial false, SVN 1, storage 512 / 465,567,744 B |
| `cm5-mc-ui-check.sh` (Playwright, live device specs) — mgmt VLAN / AP | **13/13 / 13/13** |
| `cm5-mc-ui-check.sh` + `mc-ui-specs/os-card.mjs` — mgmt VLAN / AP | **10/10 / 10/10** |
| `cm5-lan-client.sh` before Phase 0 / after | **18/18 / 18/18** (Shield row on try 2 both times = DNS-01) |
| `cm5-phase0-check.sh` (ADR 0059 0.3 + 0.5) | **9/9** |
| `cm5-wpa3-check.sh` | **7/7** |
| `cm5-cfgd-live-check.sh` (live apply, trial / confirm / revert) | **20/20** |
| `cm5-wifi-live-spike.sh` (10 live WPA2↔WPA3 switches + unconfirmed revert) | **14/14** |
| `cm5-house-check.sh` (the house plan) | **33/33** |
| Wi-Fi firmware halts | **0** |
| WPA3 counters over the batch | SAE joins 25, authorized 34, M4 failures 0, reason-49 0, reason-20 0, stale-view guard 15 (each a refuse-once + deauth `ok` after a live security change, as designed), late leaves kept 4 |

Total: 157 of 157 check rows passed. Not in this batch (proven on metal earlier this week, unchanged code): OTA update +
rollback (MB16), Wi-Fi self-heal ladder (MB15, bench image), Phase 0.4 (MB21, bench image).

Open: DNS-01 (`20261113-mb19-mb20.md`). Not run: the 72 h soak (deferred by the operator).

Nothing in this record marks a release gate complete.
