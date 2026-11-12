# Metal evidence — MB7–MB8, 2026-11-12: WPA3 PMKSA-caching reconnect fix (#1062)

**Image:** local test build = main 2a823353 + `fix/wpa3-pmksa-reconnect` (98b1aecb) + UI size PR #1059 branch,
build id `m7-4e28ead4`, `disk.img` sha256 `9dc2e01d…`, heqk8 5,213,056 B (limit 5,242,880). Known-good imgTD restored after
each batch (RESTORE RC=0). Runbook flash; serial showed `build=m7-4e28ead4`.

## Results

| Check | Result |
|---|---|
| The firmware's ASSOC_IND carries the station's (Re)Association RSNE (the main risk of the fix) | **proven** — every association logs `assoc RSNE akm=0x000fac08 …` |
| Bench Pi: join after flash; `nmcli` down/up × 3 | YES, 7–8 s each (fresh SAE each time, `pmkids=0`) |
| **Operator iPhone: Wi-Fi off/on × 2, network NOT forgotten** (the defect path) | **PASS** — `assoc RSNE akm=0x000fac08 pmkids=1 -> SAE (cached PMKSA)` then `akm=SAE … authorized=true`, both times, no SAE exchange, no wait |
| A second device (full SAE, H2E group 19) | keyed, authorized |
| Wi-Fi firmware halts | 0 (MB7 and MB8) |

Before the fix (MB6 + known-good image): the same iPhone action gave `akm=PSK m2_rx=false … deauth=true` (or `m2` with
`mic_fail=1`) until the phone's PMKSA expired or the network was forgotten.

## Not yet exercised on metal
- Unknown PMKID → deauth reason 49 → full SAE (e.g. right after a reflash with a still-cached PMKSA).
- Passphrase change clears the PMKSA cache (old PMK must not key).
- Live Wi-Fi apply with the same passphrase keeps the cached PMKSA.
- REL-08 multi-station re-join soak.

Nothing in this record marks a release gate complete.
