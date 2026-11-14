# Pi 4 wireless sensor — architecture

> A standalone **Linux bench/lab sensor** on the Pi 4, built to **harden heqk** (the CM5 AP + device). Not a
> Linux-tier product feature (ADR 0047). 802.11 is **receive-only**; LAN checks are non-root and non-disruptive.

## Context

```
                 fortress001 (dev host, this session's SSH origin)
                   │ VLAN 200 (192.168.200.1)   VLAN 100 (10.100.0.1 = CM5 WAN gw)
                   │
   ┌───────────────┴───────────────────────────────────────────┐
   │  heqk device (CM5)                                          │
   │   AP "HookProbe-Setup-R3Q1" 10.99.0.1  ·  MC 192.168.200.146│
   └───────────────┬───────────────────────────────────────────┘
                   │ Wi-Fi ch36/80 (WPA2/WPA3 transition)
        ┌──────────┴───────────┐
        │  Pi 4  hookprobe-test │   (the sensor + bench rig)
        │  eth0  10.200.0.4  ← management/SSH (user `claude`)       │
        │  wlan0 10.99.0.10  ← heqk's bench STA  +  AP-side tests   │  (shared, never reconfigured)
        │  wlan1 (RTL8811AU) ← monitor sensor, time-shared via lock │
        └──────────────────────────────────────────────────────────┘
```

## Components (all in `tools/pi4-wsensor/`, deployed to `/opt/pi4-wsensor` on the Pi)

| Piece | Role |
|---|---|
| `dongle-lock.sh` | Time-share lock for `wlan1` between the heqk bench and the monitor. Finds the dongle by USB bus (not name); records driver + NetworkManager state + the NM-profile list on acquire; on release verifies managed mode, NM-managed, same driver, and that no NM profile vanished — else keeps the lock and reports. |
| `wsensor-supervisor.sh` + `pi4-wsensor.service` | The capture service. Holds `wlan1` in monitor on the configured channel via the lock; runs two `dumpcap` rings (mgmt full-length, data header-only); extracts closed ring files to JSONL; bounces on a frame stall; **yields to heqk within ~15 s** when the lock is taken; writes `health.json` with an **honest coverage flag**. |
| `wsensor_extract.py` | tshark → JSONL event transform. Stable schema `wsensor/1`. Salted-hash of probe-request SSIDs; data frames reduced to counters (no payload). 13 unit tests. |
| `dfs-watch.sh` | Receive-only DFS-channel capture (ch52/100). **Finding: this dongle can't RX on DFS channels** — kept for a future DFS-capable adapter. |
| `m0-inventory.sh` / `m0-monitor-test.sh` | Read-only hardware inventory and the monitor-mode evidence test. |
| `install.sh` / `bootstrap-sudo.sh` | Idempotent install into root-owned `/opt`; a scoped NOPASSWD sudo rule for just the sensor's runtime ops. |

## Data flow

```
wlan1 (monitor) ──dumpcap──▶ ring pcapng (mgmt full / data headers, size+time capped)
                               │ on file close
                               ▼
                      wsensor_extract.py ──▶ events/*.jsonl  (schema wsensor/1, privacy-reduced)
                               │
            health.json ◀──────┴── supervisor (coverage on/off, drops, stalls, temp)
```

Retention is bounded: mgmt ring 500 MB, data ring 200 MB, events aged 7 days then size-capped 500 MB (config in
`/etc/pi4-wsensor/wsensor.conf`). Raw pcaps are `0700`; `health.json` + events are readable for a local dashboard.

## Time-share & safety invariants
- **One monitor radio, shared.** The dongle is heqk's SAE bench station and the monitor; the lock guarantees only
  one role at a time, and heqk pre-empts with a one-line lock write (release measured at 11 s, SLA 60 s).
- **Receive-only 802.11.** No injection, no management-frame TX (operator rule). Wireless detections are validated
  by offline PCAP replay, never over the air.
- **Non-disruptive LAN.** Scans at T2; no credential brute force; no router/device config changes.
- **Capability honesty.** `coverage=off` whenever the dongle is lent away or capture is down; DFS channels and
  6 GHz are out of scope for this adapter and said so in every report.

## Integration with Mission Control (ARCH-1)
MC is served by heqk on-device and only calls its own same-origin API (ADR 0047). A Linux sensor is therefore not a
direct MC source. Default: the sensor serves its own local dashboard. Additive, operator-gated path: heqk ingests
the `wsensor/1` events as an Observe "Wireless" source — its own ADR (signed append-only events, auth, rate limits).
