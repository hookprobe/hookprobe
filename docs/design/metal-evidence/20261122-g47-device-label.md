# G47 device rename — CM5 metal, 2026-11-22

**Image:** bench `am30S-8fdc26be` (main + E1b), CM5 bench unit, Mission Control at the management IP.
**Tool:** `tools/diagnostics/cm5-device-label-check.sh <owner-key-file>` (owner-rules `kind=device_label` on the
bench Pi's Wi-Fi MAC, an owner reboot in the middle).

```
ok  an active device on the AP to label (dc:a6:32:a4:b6:88)
   set: {"ok":true,"seq":48,"dry_run":false,"before":"labelled","after":"labelled","shadowed_by":null}
ok  /api/devices shows the owner label "Bench Pi (G47 test)"
   invalid: {"ok":false,"refused":"value: 1-31 characters: letters, digits, space . _ - ' ( ) ,"}
ok  a label with characters outside the grammar is refused (the old label kept)
   reboot: {"ok": true, "note": "restarting in 2 s; staged configuration applies on the way up"}
ok  after a reboot the owner journal still holds the device_label rule
ok  after a reboot /api/devices shows the label again once the device rejoins ("Bench Pi (G47 test)")
   remove: {"ok":true,"seq":49,"dry_run":false,"before":"labelled","after":"signed DEVICES.TXT label","shadowed_by":null}
ok  removed: the owner label is gone (now "bench-pi-wlan": the signed baseline label, or none)
ok  the remove reports what the device falls back to
DEVICE-LABEL: PASS (7/7)
```

**Notes.**
- Two earlier runs failed in the checker, not on the device:
  - The first read `/api/devices` right after the reboot, before the Pi had rejoined. The device is listed only once
    it is seen again; the rule was in the owner journal all along.
  - The second expected "no label" after the remove. The device correctly falls back to its label from the signed
    `DEVICES.TXT` baseline (owner journal over the signed baseline, ADR 0058).
- Both checks were corrected before this run.
- The test label was removed at the end, so the bench is left as found.
