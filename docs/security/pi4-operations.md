# Pi 4 wireless sensor — operations

> Day-to-day operation of the bench sensor on the Pi 4 (`claude@10.200.0.4`). Receive-only 802.11; time-shared
> dongle with the heqk metal bench; non-disruptive LAN work only.

## Install / update
```
# on the Pi, once (operator or anyone with the sudo password): installs to /opt, adds scoped sudo rule
bash ~/pi4-wsensor/bootstrap-sudo.sh
# update after editing tools/pi4-wsensor/*: re-deploy then re-run install (service keeps running)
scp tools/pi4-wsensor/* claude@10.200.0.4:pi4-wsensor/ && ssh claude@10.200.0.4 'sudo /opt/pi4-wsensor/install.sh'
```
Config: `/etc/pi4-wsensor/wsensor.conf` (channel, ring sizes, retention). Default = ch36/80 (centre 5210).

## Run / stop / status (scoped sudo, no password)
```
sudo systemctl start|stop|restart|status pi4-wsensor
cat /var/lib/pi4-wsensor/health.json            # coverage, drops, stalls, temp, lock owner
sudo journalctl -u pi4-wsensor -f               # live log
```

## Time-share with the heqk bench — THE key operational rule
The USB dongle (`wlan1`) is also heqk's second WPA3 station. The lock `/run/lock/hp-dongle.owner` arbitrates:
- heqk takes it with `echo "heqk $(date -Is)" | sudo tee /run/lock/hp-dongle.owner`; the sensor yields in ~15 s.
- The sensor takes it only when the lock is absent or says `monitor`; on release it restores managed mode,
  NetworkManager control, the same driver, and leaves heqk's NM profiles untouched (verified, else lock held).
- **Before any Wi-Fi/driver/NM change on the Pi, message the heqk session.** One SSH session at a time (the Pi
  dropped its carrier once after rapid SSH bursts).

## Health & what "coverage" means
`health.json` `coverage` is `on` **only** while monitor mode is held and frames are flowing. It is `off` (with a
reason) when heqk holds the dongle, the dongle is unplugged, or capture is down — the sensor never claims coverage
it doesn't have. Soak baseline (≈3 h, ch36): coverage_ratio 1.000, 0 stalls, 0 bounces, 0.07 % drops, 35 °C.

## Failure handling
| Symptom | Behaviour / action |
|---|---|
| Frame stall (60 s no frames) | supervisor bounces the interface automatically (`stalls`/`bounces` counters) |
| USB dongle removed | `coverage=off` reason `dongle_missing`; lock cleared; resumes when re-inserted |
| heqk takes the lock | yields ≤15 s; `coverage=off` reason `lock_held_by_heqk`; resumes when lock clears |
| Release can't verify restore | lock kept + loud log; tell the heqk session (never leave wlan1 half-restored) |
| Disk filling | rings are size-capped (500/200 MB); events aged 7 d then capped 500 MB |

## Hardware limits (state in every report)
Single 1×1 time-shared radio; **non-DFS channels only** (RTL8811AU can't RX DFS 52–64/100–144 — proven); no 6 GHz;
no control frames / noise floor (rtw88); encrypted payloads invisible; capture is part-time. For DFS over-the-air
monitoring, add an MT7612U-class adapter (operator, optional).

## Safety rules (non-negotiable)
- **Receive-only 802.11** — never transmit/inject management frames; validate wireless detections by offline PCAP replay.
- **Non-disruptive LAN** — scans at T2, no credential brute force, no router/device config changes.
- **Never scan the device's own management address from an AP client** without coordinating — pre-fix this wedged
  MC (A-03); on the fixed image it returns an immediate RST, but coordinate regardless.
- Dashboard is management-LAN only, never exposed to the internet.

## Host security (Pi)
SSH key auth as `claude`; scoped NOPASSWD sudo limited to the sensor's runtime commands (`/etc/sudoers.d/050-pi4-wsensor`);
`/opt/pi4-wsensor` root-owned; raw pcaps `0700`; SSID salt `0600`; bounded retention; the sudo password is held by
the operator, not stored in the repo or memory.
