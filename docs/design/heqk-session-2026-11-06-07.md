# heqk session record — 2026-11-06 → 2026-11-07

Branch `worktree-heqk-premetal-gaps` (worktree `.claude/worktrees/heqk-premetal-gaps`). Everything below is
committed. Living gap list: `docs/design/heqk-remaining-gaps.md`. Peer-review detail:
`docs/design/heqk-peer-review-2026-11-06.md`. Metal evidence: `~/heqk-metal-logs/2026110[67]-*`.

## 1. What was built and where it stands

| Area | What | Commits | Status |
|---|---|---|---|
| Peer review 2026-11-06 | 3 remote crash/abuse bugs, 9 firewall/availability fixes, SAVI, mgmt DHCP pinning, NAT ICMP errors (RFC 5508), RFC 1858 fragments, WPA2 STA M3 verify | `a1816dc0`…`6785b5f7` | QEMU-green; AP regressions metal-proven |
| prod-mc persistence (task #27) | snapshot survives reboot (F1), crash-consistent A/B store (F2), no writes outside a partition (F5) | `352ed658`, `ea8716c8` | **metal** |
| WAN / task #26 | mgmt VLAN DHCP, route via mgmt, configurable mgmt floor, uRPF-lite martian filter (+ false-positive fix) | `57883e30`, `b027c364`, `c92ed58f`, `7e7bc694` | **metal** (VLAN, failover, mgmt DHCP, ping, IPv6 ACL) |
| prod-mc Mission Control | SNTP wall clock, detections restored across reboot, real deployment mode, dst column, LAN host inventory, retention, UI de-mock (TopBar/hero) | `2cf37558`…`de1f70b3` | **metal** |
| Parser hardening (ADR 0050) | `[P-fuzz]` structure-aware fuzzing of every remote-reachable parser; AP parsers moved to target-independent `apparse`; mgmt handler → `mgmtproto` | `a79b2612`, `589746ac`, `3b93b3b6` | QEMU, 0 panics |
| TLS / HTTPS (ADR 0051) | `heqk-tlsprov` thin rustls provider (TLS 1.3 ChaCha20-Poly1305, X25519 + X25519MLKEM768, ECDSA P-256), EL0 TLS server with bounded excursion, MCTLS.CRT on p1, owner CA name-constrained to heqk.local + private ranges, keep-alive, HTTP→HTTPS 308, Secure cookie, handshake rate limit | `319b6541`…`22c2120f`, `8e2b4c62` | **metal**: 14 ms handshake, PQ hybrid from a browser, flood recovery |
| ADR 0049 D1 — signed POLICY.TXT | operator Ed25519 key compiled into the boot-signed image; POLICY.SIG verified before parse; anti-rollback floor | `aa24555c` | **metal**: signature OK; tampered file → `REFUSED (DigestMismatch)`, management LOCKED (fortress ping 4/4 → 0/4), AP + HTTPS up |
| ADR 0049 D3 — scans need evidence | a probe counts only when the target answered (RST/SYN-ACK) or is this device | `9cc25201` | **metal**: nmap sweep → rule 113, 93 drops |
| AP Mission Control (`apmc`) | Mission Control on 10.99.0.1 for Wi-Fi clients, HTTPS, owner sign-in, Get Online + Shield tiles from WAN facts; ARP fix for the smoltcp neighbor cache | `3b93b3b6`, `74cb1a96` | **metal**: iPhone signs in over HTTPS, pages load |
| De-mock | `/api/devices` (host inventory), "Sample data" notice on every view heqk does not back | `c4fcc501` | **metal** (served) |
| Shield DNS blocklist | operator-signed BLOCK.TXT (≤ 65,536 domains, label-suffix match); blocked queries answered on-device (A → 0.0.0.0, else NODATA); Shield tile blocked/inspected; factory `--blocklist-file` | `d2cee9b4` | QEMU + host tests green; **metal: list loads (7 domains, signature OK) but example.org NOT blocked from the iPhone** — under diagnosis (`22425ea5` adds a `[SHIELD]` heartbeat line) |
| Flows + incident drill-down | `/api/flows` from the AP NAT table (bytes each way), `/api/incidents/:id` (deterministic explanation, `model: null`, attack path), `/timeline`, honest-empty `/processes` | `d2cee9b4` | QEMU green; metal pending (same image) |

## 2. Metal-proven this session (CM5, zero-Linux image)

- AP: 80–110 Mbps, IPv6 test 10/10, VLAN 100 internet + VLAN 200 management, failover with no stall, PPPoE.
- prod-mc: SNTP, restore across power cycle, inventory, retention.
- HTTPS: browser over TLS 1.3 with X25519MLKEM768, keep-alive, 80-connection flood recovers.
- POLICY.TXT signature: accepted when signed, refused + management locked when tampered.
- D3 scan evidence: real nmap sweep detected.
- AP Mission Control: iPhone → http://10.99.0.1 → https → owner sign-in → all pages.
- eth1 (RTL8111H) without a devicetree: PCIe link trains and the NIC enumerates (`[P9] RC1 LINK UP`, `RTL8111H found`); **traffic not yet tested** (no client plugged in).

## 3. How to rebuild and flash the bench AP image

```
HEQK_AP_PSK="$(cat ~/heqk-ap-psk.txt)" HOOKPROBE_DEBUG_ACCESS=1 HEQK_KEYDIR=$HOME/heqk-sign/keys \
FEATURES=hboot,apmc,wifi-bigtx os/build/make-cm5-heqk-disk.sh --zero-linux \
  --owner-token "$(cat os/build/generated/cm5-heqk/hookprobe-heqk-cm5-74cb1a9-zerolinux-APMC-VLAN.img.owner-key)" \
  --wan-file docs/design/bench-task26/wan-vlan-mgmtdhcp.txt \
  --policy-file docs/design/bench-task26/policy-bench.txt \
  --policy-key ~/heqk-owner-ca/policy.key --policy-gen 2 \
  --mctls-file ~/heqk-owner-ca/MCTLS-cm5-6609fd646386-ap.crt \
  --blocklist-file docs/design/bench-task26/block-bench.txt
# flash (board in rpiboot):
sudo os/kernel/cm5-boot/flash-image.sh <image> --confirm-erase
```

- Owner key for the bench images: the `.owner-key` file next to each image (same token reused since `74cb1a9`).
- UI must be built first: `cd os/mission-control && PUBLIC_API_BASE='' npm run build` (node at `~/.local/node/bin`).
- Validate: `cd os/kernel && ./validate.sh` (all phases green at `d2cee9b4`).
- Fortress port-4 VLAN bench: `docs/design/bench-task26/fortress-vlan-bench.sh setup|teardown` (needs sudo). **Still up — tear down when the bench ends.**
- Serial log: `~/heqk-metal-logs/20261107-ap-serial.log` (`/dev/ttyUSB2`, 115200).

## 4. Keys and certificates (outside the repo — never commit)

`~/heqk-owner-ca/` (ca.key, ca.pem with private-range name constraints, policy.key = operator POLICY/BLOCK signing
key, MCTLS certs for CM5 6609fd646386), `~/heqk-sign/keys` (boot signing), `~/heqk-ap-psk.txt` (AP PSK).

## 5. Open — next steps

1. **Shield on metal**: `22425ea5` shows 131 client queries reach the hook but none for example.org — the iPhone
   resolved Safari via iCloud Private Relay. Confirm with Chrome/Firefox (no Relay) → `blocked` must rise.
2. Metal check of `/api/flows`, incident detail + timeline (re-run the 10.100.0.77 scan to create an incident).
3. eth1 traffic with a wired client (gap #2 of the hardware list).
4. The rest of `heqk-remaining-gaps.md`: EL0 migration of the control protocols (ADR 0050 D4), IPv6 identity
   (ADR 0049 D2), Wi-Fi TX-stall root cause, P-256 timing run, RPMB floor (operator decision), crypto audits.
5. Folder move: coordinate with the "merge hookprobe-os into hookprobe" session before moving any path above.
