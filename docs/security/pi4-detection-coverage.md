# Pi 4 wireless sensor — detection coverage

> What this bench can and cannot detect, honestly. "Observe" = metadata the sensor records; a detection rule is
> only claimed where it has been exercised against evidence (live or replayed PCAP). Receive-only; DFS and 6 GHz
> out of scope for the RTL8811AU dongle (proven).

## Wireless (802.11, from `wlan1` monitor on a non-DFS channel)

| Detection | Basis in the data | Coverage |
|---|---|---|
| Rogue / unexpected AP | beacon BSSID+SSID+security vs a baseline | ✅ data present (events carry bssid/ssid/security/akm); rule: baseline diff — validate via replay |
| Evil-twin (same SSID, unexpected BSSID) | group events by ssid, flag new bssid | ✅ data present; replay-validated rule pending |
| Unexpected open / WEP / WPA1 AP | `security` classification | ✅ classifier tested (7 classes, unit + live) |
| Security downgrade (transition / PMF change) | `security`, `pmf_required`, `akm` deltas vs baseline | ✅ fields present; **surfaced W-01/W-02 on the CM5 live** |
| Deauth / disassoc burst | `kind=deauth/disassoc` + `reason_code`, rate | ⚠️ data modelled & unit-tested; **none observed live**; validate by replay (no TX to generate them) |
| Suspicious new station | `probe_req`/`assoc_req` SA, randomization flag | ✅ data present (probe SSIDs hashed for privacy) |
| Channel change | beacon `ds_channel` / observed freq vs baseline | ✅ data present |
| Weak/obsolete capability advertised | `akm`/`pairwise`/`group`/`wps` | ✅ fields present |

**Hard gaps (adapter):** no DFS-channel capture (52–64, 100–144) and no 6 GHz — the dongle tunes but delivers no
frames on DFS; proven against ground truth. No control frames or noise floor from rtw88 (no channel-utilisation or
SNR). Monitoring is **part-time** (time-shared) and **fixed-channel** by default — hopping would add gaps.

## LAN / device (non-root, from fortress and from the AP-side client)

| Detection | Method used | Coverage / result |
|---|---|---|
| Exposed-service inventory | `nmap -sT` of the mgmt address | ✅ done — only 80/443 open, 998 filtered |
| TLS posture | openssl protocol/cipher/cert probing | ✅ done — TLS1.3-only, local CA (L-02), PQ-group not testable here |
| HTTP security headers | `curl -kI` | ✅ done — nosniff/XFO present; CSP/Referrer/Permissions missing (H-01, fixed PR #1161) |
| Login brute-force throttle | benign repeated POST, observe 429 | ✅ done — 429 after ~2 fails |
| DNS resolver posture | `dig` version.bind / ANY / ad domain | ✅ done — no version leak, no ANY amplification, ad filtering on |
| MC served on AP? (segmentation) | TCP to AP gw 80/443 | ✅ done — not served on AP (good) |
| Client → upstream RFC1918 reach | ping/TCP from wlan0 client | ✅ done — A-01 (clients reach mgmt VLAN/LAN; heqk to judge) |
| Client isolation (`ap_isolate`) | `ap-isolate-test.sh` from one client toward a 2nd client on the SSID | ⚠️ A-02: tester ready; needs a 2nd client joined to the SSID (isolation is client↔client, so one station isn't enough) |
| **Management-plane DoS** | one off-subnet TCP connection | ✅ **A-03 found + root-caused + fix-verified** (High) |

**Not in scope / not run:** UDP service scan (needs root), ARP-spoof / rogue-DHCP / rogue-RA injection tests (would
require transmitting — out of scope; validate by replay in a lab), credential brute force (prohibited).

## Headline outcome
The assessment's main yield for hardening heqk: **A-03**, an unauthenticated one-packet management-plane DoS (found,
root-caused with heqk on metal, fix verified), plus live config findings W-01/W-02/W-03 (Wi-Fi security posture) and
A-01 (client→upstream reachability) for heqk's judgment.
