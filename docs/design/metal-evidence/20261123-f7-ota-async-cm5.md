# F7: asynchronous OS-image verify / install on CM5 (2026-11-23)

Pre-soak finding 7: a synchronous OS-image verify and install stalled the AP loop for up to 9,988 ms. While that
happened, Wi-Fi clients lost service and the watchdog margin shrank. Now the AP loop advances the verify and install
jobs 64 KiB per pass (`otaimg::CheckJob` / `InstallJob`, `upload::step`). `finish` / `activate` answer at once
with `pending`, and the client polls `GET /api/upload/job` (contract: `docs/design/ota-async-upload.md`).

## Bench
- CM5, fw 7.45.265, bench WAN + management VLAN, one Raspberry Pi Wi-Fi client (WPA3).
- Images: shipping set + neuro (`hboot,apmc,wifi-bigtx,appersist,wpa3,neuro`), built from this branch:
  F7A `f7A3-fatcache` and F7B `f7B3-fatcache`.
- Runner: OTA install F7A (synchronous tool), then OTA F7B with `async=1` while the Pi pings the AP every 0.2 s.

## Result: PASS (7/7)

| Check | Result |
|---|---|
| finish and activate answer at once (`pending: verifying` / `installing`); the job runs in the AP loop | ok |
| verify + install complete asynchronously | ok, 32 s end to end |
| worst AP-loop gap across the update, before the trial reboot | **455 ms** (synchronous baseline 9,988 ms) |
| no ping lost while the image was verified and written | ok: 180 replies, no sequence gap |
| F7B trial, then COMMITTED | ok |
| no panic / crash | ok |
| bench restored to am35B (itself installed through the async path) | ok |

## The two 2.9 s steps the first metal run found
An instrumented build (`[UPLOAD-SLOW]`: any upload handler or job step over 100 ms) found two slow steps:
`verify stage 1` took 2,933 ms and `install stage 10` took 2,927 ms. Both were
`hal::abslot::inactive_slot_run` reading one FAT sector per cluster (about 1,280 reads for a 5 MiB slot).
`contiguous_run` now keeps the last FAT sector, which holds 128 entries, so a slot takes about 10 reads. It is a
pure read cache: the checks are unchanged and the abslot unit tests pass. With the cache, no `[UPLOAD-SLOW]` line
appeared during the F7A / F7B / am35B updates.

Serial capture: `~/heqk-metal-logs/20261108-relay-serial.log` (bench host), builds f7A3-fatcache / f7B3-fatcache.
