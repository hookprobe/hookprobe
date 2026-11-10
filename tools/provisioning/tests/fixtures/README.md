Synthesised serial logs (no hardware). Every line is built from the real kernel print formats:

- `[WIFI] per-device MAC`            os/kernel/kernel/src/main.rs:2840
- `[WIFI] setup AP "..." — per-device passphrase ... (label / QR: ...)`   main.rs:3027 (apcred.rs qr_payload)
- `[WIFI] no WIFI.TXT, no build-time PSK and no device-unique key ...`    main.rs:3034
- `[MC-TLS] device TLS key ... pub=<130 hex>`  os/kernel/kernel/src/tlshost.rs:421-425
- `[MC-TLS] HTTPS ready ...` / `HTTPS OFF — no certificate provisioned` / `OFF — no device root key`  tlshost.rs:410,427,431
- `[AP-MC] owner: CLAIMED|UNCLAIMED`  main.rs:3610
- `[P11-AP2] PASS(ap-config-wpa2) ... (PSK from ...)` main.rs:3338; `get_ap=.. bssid ..` main.rs:3325
- `secure boot: PASS` os/kernel/hboot/src/main.rs:280; `[HBoot-AB] PASS` main.rs:762; `[P10-B] PASS` main.rs:2858
- `[AP-MC] Mission Control on http://10.99.0.1/` main.rs:3669

The credential, MAC and public key in these files are fabricated test values (the P-256 point is a throwaway
public key). Boot logs are CRLF + an ANSI reset on purpose (a raw console capture).
