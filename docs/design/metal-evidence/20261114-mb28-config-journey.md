# Metal evidence — MB28 / MB28b, 2026-11-14 09:15–09:38 (CM5): the Mission Control config journey on metal

**Image:** main `b8158ed8` (incl. #1140 `/api/network` LAN range and #1141 bundle-sections fix), build `m28b-b8158ed8`,
delivered by OTA (HBoot identical; `cm5-ota-check.sh` 9/9). Spec: `os/mission-control/tests/ui/specs/metal/config-journey.mjs`
(UI session) via its `run.mjs`, over the management VLAN, owner signing key = the enrolled bench owner key.

MB28 (first run) used a **stale** Mission Control `dist` left in the build tree (the factory reuses an existing dist) —
the device served the pre-#1141 UI; that run is void. MB28b removed the dist and rebuilt.

| Journey | Result |
|---|---|
| 1 — firewall: add a rule → review → sign + apply live → trial → Roll back | **PASS 5/5**: sections in force reported (gen 4); review shows exactly the + line; applied live as a trial (gen 4 → 5); rolled back — the firewall in force is byte-for-byte the one before (committed) |
| 2 — Wi-Fi password change → Keep → restore | **FAIL at "wifi change: keep"**: a "Wi-Fi changed" dialog covers the trial banner's *Keep it* (click timed out). UI issue reported to the UI session, incl. the dialog's wording (it says the change keeps itself; a Wi-Fi change needs the owner's confirm) |

Device side in journey 2 was correct: `[CFGD] LIVE APPLY of generation 5: changes 0x04` (Wi-Fi), no confirm →
`reverted LIVE to generation 4 (no reboot)`; the bench Pi re-joined with the original password; `/api/config` gen 4
committed.

`/api/network` on this image: `"lan": {"ip": "10.99.0.1", "prefix": 24, "cidr": "10.99.0.0/24"}`.

Nothing in this record marks a release gate complete.
