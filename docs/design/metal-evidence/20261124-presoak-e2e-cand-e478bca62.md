# Pre-soak E2E on the clean-flashed soak candidate `cand-e478bca62` (CM5, 2026-11-24)

Operator 2026-11-24: "do an end 2 end test before the 72 hours soak, if needed do a small soak to validate before going
big"; "yes, clean rpiboot flash".

## Candidate
- Source: main at `e478bca62`, which includes #1555 (Wi-Fi self-heal UI), #1556 (async OTA), #1558 (ADR 0069 G19
  counter) and #1564 (spect diag fix).
- Feature set: the shipping set + neuro (`hboot,apmc,wifi-bigtx,appersist,wpa3,neuro`). The Mission Control UI was
  built fresh from the same commit.
- `disk.img` sha256 `f8e885a166973f69…`, `heqk8.img` sha256 `31bf0ac6edbf2b64…`.

## Clean flash (stock procedure, docs/design/heqk-flash-runbook.md)
`cm5-relay.py --backend nano --dev auto rpiboot` (boot ROM `0a5c:2712` at once) -> `flash-image.sh disk.img
--confirm-erase` -> **VERIFIED** (read-back equals the image) -> `cm5-relay.py … boot` (IN1 only) -> `secure boot: PASS`,
`[OTA] this boot: Cold build=cand-e478bca62`, AP up on the factory first-run SSID, Mission Control answering.
Device identity unchanged (`fp 941ec1e5…`).

## E2E (tools/diagnostics, shipping image, no bench features)

| # | Check | Result |
|---|---|---|
| 01 | bench baseline (enrols the owner key after the full flash, bench policy bundle) | PASS |
| 02 | Mission Control in Chromium over both paths (management VLAN + Wi-Fi client) | PASS (rerun; see note) |
| 03 | LAN client: detection + protection from a real Wi-Fi client | PASS 18/18 |
| 04 | throughput through NAT + IDS + Shield | PASS, median 96.3 Mbps (floor 60) |
| 05 | DNS under a saturating download (NET-01) | PASS, lost 0, p90 47 ms |
| 06 | Shield levels | PASS 12/12 |
| 07 | SNI block (rule 126) | PASS 3/3 |
| 08 | owner alert hook (DET-03) | PASS 7/7 |
| 09 | broadcast storm per device (rule 112) | PASS 5/5 |
| 10 | device label survives reboot | PASS 7/7 |
| 11 | OUI vendor naming (signed IEEE pack) | PASS |
| 12 | phase0 (legacy per-file WAN.TXT generation floors) | **not applicable**: with a bundle in force the device refuses per-file WAN ("a configuration bundle is in force: change this with a new bundle"), which is correct ADR 0059 behaviour; bundle-mode floors are covered by the cfgd checks |
| 13 | owner rules: journal, dry run, survives a power cycle | PASS 10/10 (rerun; see note) |
| 14 | sealed snapshot persists across a real power cycle | PASS: 11 detections survived |
| 15 | sealed evidence log across a power cycle | PASS: 12 detections kept |
| 16 | bench baseline at the end | PASS (already in force) |
| — | panic / crash / firmware trap since the flash | none |

Notes on the first run (runner, not device):
- 02 crashed before testing anything because the candidate worktree had no Playwright install.
- 13's first two points ran while the CM5 was still rebooting after check 12; the same DNS lookup answered 4/4 a
  minute later.

Both were rerun on the same board and passed.

## Small soak (3 h, `tools/diagnostics/cm5-soak.sh`, Pi browsing load, 5 min interval)

**PASS**, 12:27–15:31:
- 36 samples, 0 failed, 0 reboots or faults, 0 firmware traps;
- throughput median 95.7 Mbps (worst sample 87.2);
- DNS answered 2/2 at every sample, mostly in 3–11 ms (one sample 151 ms);
- worst AP-loop gap 615 ms (limit 2,000);
- Wi-Fi self-heal stayed `ok` with 0 kicks, bounces or reloads;
- detections kept accumulating (15 -> 20).

The CSV is under `~/heqk-metal-logs/presoak-e2e-20261124-1156/soak/` on the bench host.

## Candidate for the 72 h soak
Since this run, main gained one change in the shipping image: #1571 added a bounds check to the eMMC driver's
`cmd24`, which every eMMC write goes through. The rest (the flash stub under `flashstub`, Conductor, neuro research,
the `t0inv` readout) is outside the image. So the 72 h soak runs **`cand-23c611eb8`**: current main, shipping set +
neuro, installed by OTA over this clean-flashed board and sanity-checked (see the PR).

### `cand-23c611eb8` sanity (OTA over the clean-flashed board, 15:31–15:36)
- OTA (async verify/install) ok, then trial `build=cand-23c611eb8`, then **COMMITTED**.
- Mission Control answering.
- Throughput PASS, median 96.3 Mbps.
- LAN client PASS 18/18.
- No panic, crash or firmware trap.

**Ready for the 72 h soak (REL-05): operator start.**
