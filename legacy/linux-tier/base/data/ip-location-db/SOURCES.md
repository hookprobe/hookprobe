# Embedded offline GeoIP country database (ADR 0034 Feature 1)

This directory ships a **pinned, offline, country-level IP→ISO-3166 database** used *only* as a
**Wi-Fi regulatory-domain HINT** (never the authority — the operator-declared `wifi.country:` intent
always wins; see ADR 0034 and `base/scripts/regdomain-apply.sh`). It lets a portable SASE edge that
has a **public** WAN exit IP resolve its country with **zero network calls** (privacy-respecting,
air-gap-tolerant). Behind an upstream NAT the exit IP is unknown offline, so the GeoIP rung is
**skipped** unless the operator opts into a single external IP-echo (`HOOKPROBE_WIFI_GEOIP=1`).

## What this is

| File | Format | Size (gz) | Rows |
|---|---|---|---|
| `user-country-ipv4.csv.gz` | `start_ip,end_ip,CC` (sorted asc.) | ~1.8 MB | ~280k |
| `user-country-ipv6.csv.gz` | `start_ip,end_ip,CC` (sorted asc.) | ~1.9 MB | ~274k |

Each row is a **half-open-free inclusive range**: `start_ip,end_ip,ISO2`. Sorted ascending by
`start_ip`, so `regdomain-apply.sh`'s pure-`awk` scan early-exits (no runtime deps, sub-second at
boot). Shipped **gzipped** (24 MB → 3.7 MB) to respect the immutable-rootfs budget; the lookup
`zcat`s once at boot.

## Provenance

- **Upstream:** sapics/ip-location-db — the `user-country` database.
  <https://github.com/sapics/ip-location-db>
- **Downloaded from (raw):**
  - `https://raw.githubusercontent.com/sapics/ip-location-db/main/user-country/user-country-ipv4.csv`
  - `https://raw.githubusercontent.com/sapics/ip-location-db/main/user-country/user-country-ipv6.csv`
- **Pinned snapshot commit:** `285778fcc2338568e7e71fbd7660dcfb7d97ff5a` (2026-07-10)
- **Snapshot date staged:** 2026-07-11
- **Integrity:** SHA-256 of the *gzipped* shipped files is in `SHA256SUMS` (verified at image build).
  SHA-256 of the source **plaintext** CSVs at pin time:
  - ipv4: `1ea93eba29472f41473a3bb62fa9b17068ac0eb8d57cf5b866e8b6f5908f8023`
  - ipv6: `aa0f62aa3310fe94e9ce0f504aa695aef8a7a3be1a077a9c12e1d4402eda9b14`

## License — why THIS database (the license-clean choice for an Apache-2.0 OS image)

The `user-country` database is published under the **Open Data Commons Public Domain Dedication and
License (PDDL) v1.0** — **no attribution, no share-alike**. It is deliberately engineered PDDL-clean
by upstream (built without RIR WHOIS/IRR data), so it can be embedded in an Apache-2.0 appliance
image with **zero downstream obligation**.

The alternatives were rejected on licensing (ADR 0034, research
`docs/research/2026-07-11-wan-geoip-regdomain-research.json`):

| DB | License | Verdict |
|---|---|---|
| **sapics `user-country`** | **ODC-PDDL** (public domain) | ✅ **chosen** — no attribution, no copyleft |
| MaxMind GeoLite2 Country | proprietary EULA | ❌ requires a **paid** per-product Commercial Redistribution License to bundle |
| DB-IP IP-to-Country Lite | CC BY 4.0 | ❌ attribution / link-back obligation |
| IP2Location LITE DB1 | CC BY-SA 4.0 | ❌ attribution + **share-alike copyleft** (Apache-2.0 compatibility concern) |
| IPLocate free country | CC BY-SA 4.0 | ❌ attribution + **share-alike copyleft** |

Accuracy: country-level free-DB accuracy is 95–99%; `user-country` is ~97.5% country-code-identical
to GeoLite2 — more than adequate for a regdomain *hint* whose errors are caught by the
operator-declared authority and the on-device `wireless-regdb` compliance backstop.

## Refreshing (data-only; no code change)

Run `./refresh.sh` from this directory (needs network). It re-downloads both CSVs, verifies they are
non-empty and sorted, re-gzips them in place, updates `SHA256SUMS`, and prints the new upstream
commit + date to paste into the "Pinned snapshot commit" line above. Then rebuild the image so the
refreshed DB is staged into `/usr/share/hookprobe/geoip/`.

A refresh is **optional and infrequent** — a stale country DB only degrades the *hint* (the operator
intent + `wireless-regdb` still govern compliance), and an air-gapped box never needs it.
