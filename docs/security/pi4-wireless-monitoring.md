# Pi 4 wireless monitoring — event schema & field contract

> **Stable contract** for the sensor's output, so a consumer can map it later (a local Pi dashboard now; a
> possible heqk evidence-ingest path per **ARCH-1**, which would be its own ADR — sensor auth / rate limits /
> evidence mapping / ADR 0047 fit, with the natural design being the **sensor pushing signed, append-only events**
> that heqk verifies; **not** heqk pulling from a Linux host).
> **Schema id:** `wsensor/1` (field `schema` on every event). Bumped only on a breaking change.
> **Producer:** `tools/pi4-wsensor/wsensor_extract.py` (tshark field extraction; receive-only).

## Output

One **JSON Lines** file per closed capture-ring file: one object per 802.11 **management** frame, plus a single
`data_summary` object per file (data frames are reduced to per-(BSSID, station) counters — **no payload is read**).

## Common fields (every event)

| Field | Type | Meaning |
|---|---|---|
| `schema` | str | `"wsensor/1"` |
| `event_id` | str | UUIDv4 |
| `ts` | float | epoch seconds (frame time) |
| `sensor` | str | hostname of the sensor |
| `iface_role` | str | `"monitor"` |
| `classification` | str | `"observed"` (vs `inferred` / `simulated` — only `observed` is produced here) |
| `kind` | str | `beacon` `probe_resp` `probe_req` `assoc_req` `assoc_resp` `reassoc_req` `reassoc_resp` `auth` `deauth` `disassoc` `action` `action_noack` `data_summary` |
| `source` | str | capture filename |
| `freq_mhz`,`channel` | int/null | radio frequency and derived channel |
| `dbm` | int/null | antenna signal (no noise floor from rtw88 → no SNR) |
| `bssid`,`sa`,`da` | str/null | addresses |
| `protected` | bool/null | 802.11 Protected Frame bit |

## Per-kind fields

- **beacon / probe_resp:** `ssid`, `hidden`, `ds_channel`, `security` (`OPEN` `WEP` `WPA1` `WPA2-PSK`
  `WPA2/WPA3-transition` `WPA3-SAE` `OWE` `WPA2/3-Enterprise` `UNKNOWN`), `akm[]`, `pairwise[]`, `group`,
  `pmf_capable`, `pmf_required`, `sae_h2e`, `wps`, `country`, `vht_width`, `vht_center0`.
- **probe_req (privacy):** `wildcard`, `sa_randomized`, and for a directed probe **`ssid_hash`** (salted
  SHA-256, 16 hex) + **`ssid_len`** — the remembered-network name is **never** emitted in clear.
- **deauth / disassoc:** `reason_code`.
- **auth:** `auth_alg`, `status_code`. **assoc_resp / reassoc_resp:** `status_code`.
  **assoc_req / reassoc_req:** `ssid`.
- **data_summary:** `ts_first`, `pairs[]` of `{bssid, sta, frames, last_dbm}`.

## Privacy stance (spec §5)
No payloads; data frames are counters only. Directed probe-request SSIDs (which reveal a device's remembered
networks) are stored only as a salted hash + length; the salt lives at `/var/lib/pi4-wsensor/ssid.salt` (0600) and
never leaves the device. Beacon/probe-response SSIDs are public broadcasts and kept in clear.

## Known limitations (repeat in every coverage report)
Single time-shared 1×1 radio; fixed-channel only; **no control frames and no noise floor** (rtw88 monitor);
encrypted payloads invisible; hopping would create gaps; coverage is part-time and `health.json` reports
`coverage=off` whenever the dongle is lent to the heqk bench.

## Health file
`/var/lib/pi4-wsensor/health.json`: `coverage` (`on`/`off`) + `reason`, `lock_owner`, `freq_mhz`/`width_mhz`,
`rx_packets`/`rx_dropped`/`rx_pps`, `last_frame_age_s`, dumpcap liveness, `stalls`/`bounces`/`yields`,
`coverage_ratio`, `temp_c`, `disk_used_pct`, and a `limits` string. `coverage` is `on` only while monitor mode is
held **and** frames are flowing — it never claims coverage it does not have.
