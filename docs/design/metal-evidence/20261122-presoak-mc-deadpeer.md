# Pre-soak finding 1 on CM5: Mission Control slots pinned by vanished clients (2026-11-22)

**Tool:** `tools/diagnostics/cm5-mc-deadpeer-check.sh` (`PI_SUDO_FILE`, `OWNER_KEY_FILE`).

**Method.**
1. The bench Pi signs in once over Wi-Fi.
2. It opens **8 live SSE streams** (`/api/stream`) to Mission Control at 10.99.0.1, from source ports 45100–45107.
3. A Pi-only `nft` rule silently drops exactly those 8 connections. No FIN and no RST reach the AP, which is what a
   laptop going to sleep or a phone leaving Wi-Fi looks like.
4. From t = 20 s, a 9th, normal client on the Pi polls `/api/health` every ~5 s.

At the end the rule is removed, the holder is killed, and the test session is signed out.

| Image | Contents | 9th client first served | Result |
|---|---|---|---|
| `am30S-8fdc26be` | main before #1468 | **never** (23 refusals in 240 s) | slots pinned; AP-side Mission Control unreachable for everyone |
| `am35B-78cb7095` | main with #1468 (MC sockets: 60 s silence timeout, 15 s keep-alive) | **t = 66 s** (60 s timeout + poll interval), then every poll | slots reaped; no panic or crash |

**Notes.**
- On the pre-fix image, the bench recovered only because the test's cleanup let the Pi's kernel answer the
  retransmissions with RST. A peer that is really gone never does that.
- An earlier variant, with 8 idle TLS sessions and no request, did **not** pin slots on the pre-fix image: the server
  ends idle sessions itself. The pinning case is a live SSE stream, the dashboard's.
