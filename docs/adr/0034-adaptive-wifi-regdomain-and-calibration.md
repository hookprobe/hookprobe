# ADR 0034 — Adaptive Wi-Fi: dynamic regulatory domain (from the WAN exit) + on-the-fly channel/width auto-calibration

**Status:** 🟢 Accepted (implemented, metal-validated 2026-07-16 — see Update 2026-07-16 below). Pure, testable core IMPLEMENTED + unit-tested
(`crates/hookprobe-manifest/src/wifi_calibrate.rs`, 31 unit tests; a byte-identical refactor of
`wifi_cfg.rs` that exposes a forced-width per-rung renderer + a `country_code`-never-`auto`
sanitiser; 53 wifi tests total green, 0 new clippy warnings). **Feature 1 (dynamic regdomain) is now
WIRED for the upcoming consolidated image rebuild:** a boot-ordered oneshot
(`base/units/hookprobe-regdomain.service` + `base/scripts/regdomain-apply.sh`) resolves the country
(offline-first) and applies `iw reg set` + writes `/run/hookprobe/wifi-country` BEFORE hostapd
starts; the supervisor's reconcile reads that file and resolves `wifi.country: auto`/absent → the
detected CC so hostapd `country_code` matches the kernel regdomain and is never `auto`; the shipped
`network.example.yaml` no longer hardcodes `country: GB` (now `auto`).
**Update 2026-07-11 (this change) — Feature 1 hardened per deep research
(`docs/research/2026-07-11-wan-geoip-regdomain-research.json`):** the two on-metal GAPs are closed.
(GAP-R1) `regdomain-apply.sh` now **always exits 0** and always writes a VALID token (`00` if nothing
resolves) — the oneshot can never enter `failed` nor leave the run-file empty. (GAP-H2, closed by
making `00` rare) an **offline GeoIP rung** was added: the box's own **public WAN exit IP** is looked
up against an **embedded ODC-PDDL country database** (sapics/ip-location-db `user-country`,
`/usr/share/hookprobe/geoip/*.csv.gz`, ~3.7 MB gzipped) with a pure-`awk` binary-ish scan — **no
network, no identity leak**; and a **last-known-good cache** (`/var/lib/hookprobe/regdomain-lkg`) makes
a box that resolved a country once stay on it across a briefly-down-WAN boot. The wifi_cfg.rs
unresolved-country 5 GHz→2.4 GHz/HT20 fail-safe is **kept** as belt-and-suspenders. Feature 2's runtime feedback
loop is SKETCHED as a working oneshot + unit (`base/scripts/wifi-calibrate.sh`,
`base/units/hookprobe-wifi-calibrate@.service`), shellcheck-clean, per-rung rendering still a
minimal inline mirror pending the `--wifi-calibrate` supervisor subcommand. **Not on-metal-validated
end-to-end as a service yet** (the underlying facts ARE metal-proven — regdomain detection returned
RO from the modem MCC live during this work; see "Proven vs pending"). This work is
correctness/compliance only — it does NOT change throughput (the CM5's lower-than-expected VHT80
rate is a separate external-antenna hardware issue). No image rebuild in this change.
**Update 2026-07-11b (this change) — the AUTONOMOUS two-phase flow (W1–W4), SPEC-ONLY (boxes
removed; validated via the gate ladder, no metal):** four gaps proven on-metal (Pi4 + CM5 boot
journals) are resolved by design here — see the new decisions **D11–D14** and the **Validation
Plan** below. The single load-bearing correction to the earlier claim: the boot regdomain oneshot
runs *before the WAN is up*, so the offline-GeoIP-from-the-ISP rung cannot run at boot; the
autonomous "detect the country from the WAN exit IP" therefore MUST be a **second phase** fired when
the WAN gains a route + a public exit IP. And the world domain must be signalled to hostapd by
**OMITTING** the `country_code` line, never by emitting `country_code=00` (which hostapd rejects at
config-parse on any band — proven live: deleting the line makes hostapd start).
**Update 2026-07-11c (status-truth, product-steward) — W1–W4 are NO LONGER spec-only: they are
IMPLEMENTED + gate-ladder-validated (metal still pending).** The earlier "SPEC-ONLY" framing above
is now stale. code-developer landed all four (`wifi_cfg.rs` omit-`00`, `wifi_calibrate.rs`
`pick_24_channel`/`next_rung_action`, `lan.rs`/`multi_wan.rs` `RequiredForOnline`,
`hookprobe-regdomain-reresolve.service`, `regdomain-apply.sh` re-resolve, `wifi-calibrate.sh`
verify-retry) and verification-engineer ran the full ladder GREEN (T1: 469 `hookprobe-manifest`
tests + clippy clean; T2: real `hostapd -dd` dry-parse proving W2, `systemd-analyze verify` 0
ordering cycles; T3: QEMU arm64 boot proving W1 ordering + W4 `network-online.target` reached +
the reresolve no-op — see BuildPlan Change Log 2026-07-11 and the updated "Proven vs pending" table
below). The ADR **stays 🟡 Proposed** only because the *radio-behaviour* half (real brcmfmac DFS
bounce / clean-restart-holds-VHT80, GeoIP-from-a-real-ISP-exit-IP end-to-end, real 2.4 GHz survey)
is not metal-validatable without a box (boxes physically removed) and the code-developer/
security-auditor reviews + a CM5/Pi5 metal gate remain the acceptance criteria.
**Update 2026-07-16 (status-truth, product-steward) — ACCEPTED: the radio-behaviour half is now
metal-validated on BOTH Pi4 + CM5.** The boxes returned and the combined edge-kernel image passed a
comprehensive on-metal pass: **autonomous Wi-Fi landed VHT80-ch40 / 80MHz / ~450Mbps** with band-LKG
persistence, and the **ML learning model is proven live** (records trials, resumes-at-proven-rung,
skips-known-bad, Beta-decay accumulation), with the DFS-CAC timer, survey optimizer, warm-upgrade,
and the boot auto-start fix all exercised (D15–D44 landed this session). This clears the sole reason
the ADR was held at Proposed. **[SUPERSEDED 2026-07-17 by BUG-W7 — see the extension below.]** This
paragraph previously claimed as an "honest residual" that "the BCM43455 brcmfmac FullMAC still will not
hold VHT80 (collapses to ch140); stable is ch36/HT20." **That is now disproven:** both boards land AND
HOLD `5GHz-VHT80-ch40` (reported as ch36/80MHz/center 5210, ~250 Mbit/s) — the "collapse to ch140" was
a channel-*naming* quirk plus a false `ChanspecFailStorm` verdict (an 80 MHz block reports its primary
as the block's lowest channel), NOT a hardware ceiling. See Extension BUG-W7. Real cross-border
GeoIP-from-a-live-ISP-exit-IP remains opportunistically validated (depends on the WAN the box is behind).

**Deciders:** os-architect (author). Pending review: code-developer (the supervisor subcommand +
reconciler wiring that starts/masks the supplicant and invokes the loop), security-auditor (the
GeoIP outbound-lookup privacy stance + the supplicant-mask privilege path), verification-engineer
(a metal gate for the calibration loop on a CM5/Pi5), telemetry-analyst (per-platform radio-caps
truth: which rung each radio actually settles on).

**Relates to:** the `sase-edge-default` posture (portable edge that may cross borders — the reason
the regdomain cannot be hardcoded), the `wifi-brcmfmac-caps` field findings (the on-metal source of
truth this ADR encodes), [ADR 0023](0023-enforcement-separation.md) (compliance-as-safety: never
transmit outside the detected domain, exactly as we never drop a legit customer's packet),
`crates/hookprobe-manifest/src/wifi_cfg.rs` (`vht80_params`/`render_ap` this builds on) and
`multi_wan.rs` (the WAN model whose "WAN up / WAN change" event triggers re-detection).

## Context

HookProbe OS is a portable SASE edge: the same box may boot in Romania this week and the UK next.
Two operator-declared Wi-Fi needs fall out of that, both grounded in on-metal findings (CM5, serial
console, 2026-07-10):

1. **Compliance.** The regulatory domain (allowed channels, TX power, DFS obligations) is a legal
   property of the box's *current physical location* — which follows the WAN exit, not a build-time
   constant. Hardcoding `country_code=GB` is wrong the moment the box moves. Regdomain must be
   DETECTED at runtime and re-evaluated when the WAN changes.

2. **Throughput without fragility.** A bare `hw_mode=a channel=36 ieee80211n=1` AP ran HT20
   (~78 Mbit/s) on a radio whose `iw phy` advertises VHT80 (~433 Mbit/s PHY, 1SS). The obvious fix
   — hardcode a VHT80 block — is *also* wrong: the width that holds is radio- and
   environment-dependent, so the width must be DISCOVERED and VERIFIED at runtime, with a graceful
   step-down when a rung doesn't hold.

### The corrected brcmfmac root cause (this supersedes the initial premise)

The first framing of this work assumed the Pi/CM onboard **BCM43455 (brcmfmac FullMAC) cannot hold
VHT80 in AP mode** — a correct VHT80 block appeared to make the firmware reject the wide chanspecs
(`brcmf_set_channel: set chanspec 0xd0XX fail, reason -52`) and collapse to ch140/20 MHz with zero
clients. **That conclusion was wrong**, and this ADR records the correction proven live on the CM5:

- **VHT80 IS a stable, reachable top rung on brcmfmac.** With the fix below, the CM5 came up on
  ch40 / 80 MHz / center-5210 and a client held **351 Mbit/s** (up from 78). It did not collapse.
- **The real cause of the ch140/20 MHz collapse was `wpa_supplicant`** — enabled by default and
  auto-starting — **scanning the AP radio `wlan0` and yanking hostapd off-channel.** After
  `systemctl mask wpa_supplicant` + restarting `hookprobe-hostapd@wlan0`, VHT80 came up and held.
- **The brcmfmac-safe VHT80 hostapd block** is exactly what `wifi_cfg::vht80_params`/`width_lines`
  already emit — `ieee80211n=1` + `ht_capab=[HT40±][SHORT-GI-20][SHORT-GI-40]` + `ieee80211ac=1` +
  `vht_oper_chwidth=1` + `vht_oper_centr_freq_seg0_idx=42` + `vht_capab=[SHORT-GI-80]`, and
  **nothing else**. It must NOT include `[MAX-AMSDU-7935]`/`[MAX-MPDU-11454]` (outside the radio's
  advertised VHT cap `0x00001020`) nor `spectrum_mgmt_required`/`ieee80211h`; the FullMAC firmware
  rejects any of those and hostapd exits. The existing helper is therefore correct as-is.
- **Regdomain-from-WAN confirmed working:** the CM5 detected `RO` (matching its WAN exit, the
  fortress uplink) and set it correctly.

The step-down ladder still matters — a DFS bounce, a genuinely weaker radio, or residual contention
can still make a given rung fail — so the design keeps "try widest, VERIFY it held, step down if
not." It just no longer treats brcmfmac as HT20-capped.

## Decision

### D1 — Two capabilities, one intent surface, config as a generated artifact

The operator declares WHAT (`wifi.country: auto|GB|…`, `wifi.optimize: max-throughput|conservative`);
the reconciler + calibration loop produce the hostapd conf and regdomain. This is the AEGIS pattern:
config is a generated artifact, never the interface. `wifi.country` already exists in `WifiIntent`
and **always wins** when set to a real 2-letter code (`auto`/blank = "let detection decide").

### D2 — Deterministic core in `hookprobe-manifest` (pure, testable), runtime feedback in a service

Everything decidable without touching a radio is a pure function in
`crates/hookprobe-manifest/src/wifi_calibrate.rs`, unit-tested, no network, no shell:

- `decide_country(CountryInputs) -> CountryDecision` — the priority ladder (D3).
- `reg_channels(cc) -> RegChannels` — regdomain → allowed non-DFS channels (D4, coarse; the kernel
  `wireless-regdb`/CRDA is the authoritative compliance enforcer after `iw reg set`).
- `supplicant_policy(&[(iface, role)]) -> Vec<SupplicantPolicy>` — the AP-bring-up prerequisite (D5).
- `candidate_ladder(RegChannels, RadioCaps) -> Vec<Rung>` — the best→safe ladder (D6).
- `render_rung_conf(...)` — per-rung hostapd conf, delegating to `wifi_cfg::render_ap_rung` so the
  security block (WPA2-PSK/EAP), SSID and banner are produced by the SAME code as the normal path.
- `verify_rung(&Rung, &ObservedAp) -> Stability` — classify what the radio actually did (D7).
- `start_rung(&[Rung], cached_label) -> usize` — hysteresis: reboot at the proven rung (D8).
- `CalibrationOutcome::to_json()` — the status/evidence artifact (D9).

The runtime half — which only exists because it needs live feedback (AP active? width matched?
dmesg chanspec-fail? client associated?) — is a oneshot service that gathers inputs, sets the
regdomain, applies each rung, observes the radio, and steps down. It calls the pure core for every
decision. Refactor note: `wifi_cfg::render_ap` gained an internal `force: Option<(channel, width)>`
and a public `ChanWidth` + `render_ap_rung`; the default (`force = None`) path is **byte-identical**
to before (all 18 pre-existing `wifi_cfg` tests still pass unchanged).

### D3 — Feature 1: country detection priority ladder (offline-capable, privacy-respecting)

`decide_country` resolves the regulatory country in strict priority order, each source used only if
it yields a plausible ISO code (an unknown input falls through rather than guessing — a wrong
country over-permits power/channels, so unknown must degrade toward the *more restrictive* world
domain):

| Prio | Source | Confidence | Notes |
|---|---|---|---|
| a | **Operator intent** (`wifi.country: GB`) | 100 | The **AUTHORITY**; ALWAYS wins; `auto`/blank ≠ override (Meraki model — GeoIP is only a hint) |
| b | **Last-known-good** cache | 85 | Fail-safe boot stability (WAN/modem may not be up yet); skipped on a WAN-change re-eval so a moved box re-detects. `/var/lib/hookprobe/regdomain-lkg`, never `00` |
| c | **Cellular modem MCC** → ISO | 90 | Most authoritative LIVE source for a moving box — it *is* the location; offline. `mcc_to_iso` table |
| d | **Offline GeoIP** of the PUBLIC WAN exit IP | 75 | **Local DB lookup, no leak → on by default.** Skips silently when behind NAT (no public exit IP) unless the operator opts into an external IP-echo (see D10a) |
| e | **System timezone** → ISO | 40 | Offline, approximate (a TZ can span countries); `timezone_to_iso` table |
| f | **World `00`** | 0 | Final fallback — most conservative (lowest power, fewest channels); the GAP-R1 terminal, never `auto`/empty |

The runtime logs (and the artifact records) which source decided, with its confidence. **Honest
ordering note:** the last-known-good rung is *consulted* before the live modem/GeoIP at boot (for
stability against a transiently-down WAN) yet is *scored* below a live modem reading (confidence 85 <
90) — it is a cached hint that may be stale if the box moved with the WAN down. The runtime
WAN-change re-eval (`wifi-calibrate.sh`) passes `HP_REGDOMAIN_SKIP_LKG=1` so a genuine move
re-detects live rather than sticking to the cache, then refreshes it.

### D4 — Feature 1: regdomain → allowed non-DFS channels (compliance)

`reg_channels(cc)` returns the coarse non-DFS channel set the ladder may PROPOSE:
UNII-1 (36–48) is legal for indoor low-power AP use in essentially every target domain; UNII-3
(149–161) is added only for FCC-style domains (US/CA/APAC/Americas), excluded for ETSI (EU/GB) AP
use; the world `00` domain gets UNII-1 only and no 2.4 HT40. **DFS channels (52–144) are excluded
everywhere** — an unattended edge AP must not gamble on radar CAC. This table is only a guardrail so
the ladder never proposes an obviously-illegal channel; **the kernel `wireless-regdb`/CRDA is the
real compliance backstop** — after `iw reg set <CC>` it clamps TX power, channels and DFS to the
domain, and hostapd refuses a config outside it. **Compliance is the point: transmit power, allowed
channels and DFS rules follow the detected regdomain; the box never transmits outside it.**

### D5 — Feature 2 PREREQUISITE: no supplicant contention on the AP radio (the durable bug fix)

The corrected root cause becomes a hard, deterministic prerequisite. `supplicant_policy` maps each
manifest radio's ROLE to an action: **STATION radios (USB-dongle uplinks) → `Start` a supplicant;
AP-role (and any unknown-role) radios → `Mask`.** A `wpa_supplicant` on an AP radio scans it and
yanks hostapd off-channel — so it must never run there. This is itself a durable defect to fix:
`wpa_supplicant.service` is enabled by default. The runtime masks the supplicant on the AP interface
(and the global catch-all when there is no explicit station supplicant) BEFORE calibrating. Bringing
the AP up cleanly = "no supplicant on the AP radio" first.

### D6 — Feature 2: the candidate ladder (best → safe)

`candidate_ladder(reg, caps)` emits, within the regdomain's allowed channels and the radio's
advertised `iw phy` caps:

1. **5 GHz VHT80** on the lowest allowed non-DFS 80 MHz block (36 preferred, else 149) — top rung,
   reachable on brcmfmac once D5 holds.
2. **5 GHz HT40** ch36.
3. **5 GHz HT20** ch36 — the safe 5 GHz rung.
4. **2.4 GHz HT40** ch6 — only where the domain + radio allow it.
5. **2.4 GHz HT20** ch6 — the universal floor; always last, so the ladder is never empty and the AP
   is never left down.

Rungs the radio can't do (no 5 GHz, no VHT80/HT40 cap) or the domain forbids are omitted. A
softMAC/USB dongle that advertises VHT80/HE simply keeps the top rung; a weaker radio starts lower —
capability-driven, never hardware-branched.

### D7 — Feature 2: stability verification (verify each rung actually HELD)

For each applied rung the runtime observes `iw dev … info` (operating channel + width), the
post-apply dmesg window (chanspec-fail count), the AP unit's active state, and (if a client is
present) association. `verify_rung` classifies, most-diagnostic-first:

`Down` (unit inactive) → `ChanspecFailStorm` (≥2 `set chanspec … fail`) → `WidthCollapsed`
(operating channel/width ≠ requested — the off-channel/collapse detector) → `ClientFailed` (a
client that was expected never associated) → `Stable`. Only `Stable` is kept; anything else steps
DOWN to the next rung. A single stray chanspec line during a restart is tolerated (threshold 2).

### D8 — Feature 2: hysteresis + last-known-good cache

`start_rung(ladder, cached_label)` starts the loop at the PROVEN rung for this (radio, regdomain),
not the top — no re-thrash of a rung already shown to fail. The full ladder (from the top) re-runs
**only** on: a regdomain change, a radio/driver change, boot, or an explicit operator request —
never spontaneously. A stale cache label not in the current ladder (domain changed) restarts from
the top.

### D9 — Status/evidence artifact

`CalibrationOutcome::to_json()` writes `/var/lib/hookprobe/wifi-calibration.json`: the chosen country
+ source + confidence, every rung tried with its verdict, the winning rung, and a timestamp. This is
the observability surface for the operator (Mission Control) and for telemetry-analyst (per-platform
radio-caps truth — which rung each radio really settles on).

### D10 — Standalone / air-gap privacy stance: an EMBEDDED OFFLINE GeoIP DB (revises the earlier "no DB by default")

The box is standalone-by-default, no cloud. The deep research
(`docs/research/2026-07-11-wan-geoip-regdomain-research.json`, finding 3) confirmed that an **online**
GeoIP API (ip-api.com, ifconfig.co, Cloudflare trace…) leaks the box's identity to a third party and
fails air-gapped — so we do **not** call one. Instead we embed an **offline** country DB and look up
the box's *own* WAN exit IP locally: a **purely local** operation, no packet leaves, works
air-gapped. This **revises** the ADR's original stance (which declined *a MaxMind DB* on
license/footprint grounds — that specific objection still holds; the alternative chosen here does
not).

**D10a — the DB choice + license rationale.** The single **license-clean** offline IP→country DB for
an Apache-2.0 OS image is **sapics/ip-location-db `user-country`** under the **ODC-PDDL** (public
domain — *no attribution, no share-alike*), engineered PDDL-clean upstream (research finding 1). The
rejected alternatives, and why, are recorded in `base/data/ip-location-db/SOURCES.md`: MaxMind
GeoLite2 needs a **paid** per-product Commercial Redistribution License; DB-IP Lite is CC BY 4.0
(attribution); IP2Location LITE and IPLocate are CC BY-SA 4.0 (**share-alike copyleft** — an Apache-2.0
compatibility hazard). Accuracy is ~97.5% country-identical to GeoLite2 — ample for a *hint*.
**Footprint:** the IPv4+IPv6 CSVs are ~24 MB plaintext → **~3.7 MB gzipped**, shipped `.csv.gz` and
`zcat`-scanned once at boot (pure `awk`, no runtime dep, no MMDB parser). The pin (upstream commit,
snapshot date, SHA-256) and a `refresh.sh` are in `base/data/ip-location-db/`. Staged to
`/usr/share/hookprobe/geoip/` on all three build paths (Containerfile, mkosi amd64, mkosi arm64), and
build-asserted present.

**D10b — the NAT / exit-IP nuance (the crux).** The offline DB needs the box's **public** exit IP.
`regdomain-apply.sh` derives it from the default-route (WAN) interface's global address:
- If the WAN iface already holds a **public** (non-RFC1918, non-CGNAT-100.64/10, non-link-local)
  address, the lookup is **fully offline** — the common non-NAT case (e.g. a PPPoE/DHCP public IP).
- If the WAN iface holds only a **private** address (behind an upstream NAT/CGNAT — e.g. this lab's
  CM5 behind fortress `10.200.0.0/28`), the exit IP is **unknown offline**, so the GeoIP rung
  **SKIPS** (falls through to timezone/world) — **unless** the operator opts in
  (`HOOKPROBE_WIFI_GEOIP=1`) to a **single external IP-echo** that returns our public IP, which we
  then still resolve **offline** against the DB. Default = offline-only, **no outbound identity
  leak**. `HOOKPROBE_WIFI_GEOIP` now gates *only* this behind-NAT echo (the offline lookup on a public
  WAN IP is always allowed because it is local).

**D10c — last-known-good cache.** Once any rung resolves a real country it is persisted to
`/var/lib/hookprobe/regdomain-lkg` and consulted as an early boot rung (prio b) — so a box that
resolved `RO` once stays `RO` even if the WAN is briefly down at the next boot; the WAN-change re-eval
skips it to allow live re-detection after a physical move (see D3).

**Ordering caveat (honest):** the regdomain oneshot runs *before* the network reconcile, so on a
**first** boot the WAN may not yet hold an address when the GeoIP rung runs → it resolves via
timezone/world that boot, and the LKG + the runtime WAN-change re-eval converge it thereafter. The
deterministic path for a box that must be right on first transmit is the **operator-declared**
`wifi.country` (which is also what compliance wants — see the legal finding). The seam
(`CountryInputs.geoip_cc`) still accepts either an offline-DB or an online result without code change.

### D11 — Two-phase regdomain (W1): boot fast-path + WAN-online re-resolve

The boot oneshot (`hookprobe-regdomain.service`) runs `After=hookprobe-bootstrap ModemManager`,
`Before=hookprobe-network-reconcile` — i.e. **before the WAN is up**. It therefore CANNOT do the
GeoIP-from-the-ISP-exit-IP lookup at boot. Split the flow:

- **(a) Boot fast-path** — the existing oneshot resolves a VALID regdomain WITHOUT the WAN:
  `operator-intent > cached-LKG > cellular-MCC > timezone > unresolved`. It `iw reg set`s the result
  and writes `/run/hookprobe/wifi-country`. When nothing resolves it writes the world token `00`
  (the **UNRESOLVED** signal — see D12), so the AP still comes up immediately. The GeoIP rung is
  intentionally NOT reached here (no public WAN IP yet); it belongs to phase (b).
- **(b) WAN-online re-resolve** — a NEW oneshot `hookprobe-regdomain-reresolve.service`,
  `After=network-online.target hookprobe-network-reconcile.service`, runs `regdomain-apply.sh` in
  re-resolve mode (`HP_REGDOMAIN_SKIP_LKG=1`). The WAN now holds a public exit IP, so the
  **offline** GeoIP rung resolves the ISP country. If — and only if — it yields a REAL 2-letter code
  that DIFFERS from the current run-file value, it: writes the run-file + LKG, **STOPs hostapd**
  (so the radio is idle), `iw reg set <CC>` (safe now — no DFS bounce), then re-runs the reconcile
  (which re-renders `country_code=<CC>` + cleanly restarts hostapd + the verify loop). **Idempotency
  guards:** (1) no restart unless the CC actually changed; (2) NEVER downgrade a real CC to `00` on a
  transient WAN blip (a re-resolve that yields `00`/unresolved is a no-op when the run-file already
  holds a real CC). `network-online.target` must not hang on the AP radio — the AP iface's generated
  `.network` sets `RequiredForOnline=no` (WAN sets `RequiredForOnline=routable`). A later runtime WAN
  change (box physically moved) re-fires the same script via a networkd-dispatcher `routable.d` hook
  on the WAN iface (reuse, not new logic).

### D12 — World/unresolved fail-safe (W2): OMIT `country_code`, never emit `=00`

hostapd REJECTS `country_code=00` at config-parse on ANY band (`Invalid country_code '00'`) → the
interface never initialises → **no SSID**. Proven live: deleting the line makes hostapd start on the
kernel-default domain. So `wifi_cfg::render_ap` treats the sanitised token `00` as **UNRESOLVED =
"omit the country_code line entirely"** (and omit `ieee80211d`), and pins the AP to **2.4 GHz / HT20
/ best non-overlapping channel** (D13) — the one band+width the kernel-default/world domain always
permits. A REAL 2-letter CC emits `country_code=<CC>` + `ieee80211d=1` (advertise the country IE —
correct only with a real country) and the intended band/width (5 GHz VHT80 per the ladder). "AP up
on 2.4 GHz" >> "no AP"; phase (b) or an operator `country:` then upgrades it to 5 GHz. This REPLACES
the earlier fail-safe that kept `country_code=00` (which does not actually start hostapd).

### D13 — 2.4 GHz best-match failover channel (W3)

`pick_24_channel(survey) -> u32` picks a non-overlapping 2.4 GHz channel (1/6/11): with a survey
(from `iw dev … survey dump`, gathered by the runtime AFTER the AP is up — never at boot, to avoid
the W4 scan race) it returns the least-congested of 1/6/11, tie-break lowest; with NO survey
(the boot path) it returns the deterministic default **6**. Pure + unit-tested.

### D14 — DFS-bounce-safe bring-up (W4): make the verify-retry ladder actually run

With a valid CC + 5 GHz VHT80, a transient scan racing hostapd's first bring-up makes brcmfmac
bounce to ch140/20 MHz (DFS, unusable); a CLEAN restart (no competing scan) holds VHT80. Two parts:

- **Eliminate the boot scanner.** `wpa_supplicant` is masked (preset + `supplicant_policy` — the
  proven root cause). The AP iface's `.network` sets `RequiredForOnline=no` so networkd does not
  block on / cycle it. hostapd owns the radio (regdomain already set before it starts). The clean
  restart in the verify loop is the durable backstop regardless of any residual transient.
- **Verify-retry state machine (the ADR ladder, made to RUN).** `hookprobe-wifi-calibrate@<ap>` is
  started at boot by `network-apply.sh` right after hostapd (it was a never-enabled template). It
  starts at the cached-good rung (`start_rung`), applies the rung, does a **clean restart** (stop →
  ensure no scan → start), observes (`iw dev … info` + dmesg), and calls the pure
  `verify_rung` + the NEW pure `next_rung_action(verdict, attempt, max_retries)`: a
  `WidthCollapsed`/`ChanspecFailStorm`/`Down` first triggers a **clean-retry of the SAME rung** (the
  transient-bounce case — VHT80 holds on retry) up to `max_retries`, and only then **steps DOWN**
  the ladder (VHT80 → HT40 → HT20 → 2.4/HT20 floor). It does NOT re-resolve the country or re-set
  the regdomain at boot (that is phase (a)/(b)); it only converges the width.

## Validation Plan (gate ladder — NO metal)

The boxes are removed; everything below is asserted by the verification-engineer via the existing
gate ladder BEFORE any build/flash. What CANNOT be proven without a radio is called out honestly.

- **T1 unit tests (pure core, `wifi_cfg` + `wifi_calibrate`):**
  - `render_ap` unresolved (`country=="00"`) → conf contains NO `country_code=` and NO `ieee80211d`,
    contains `hw_mode=g` + a 1/6/11 channel + `ieee80211n=1`, and NO `ieee80211ac`/`vht_*`.
  - `render_ap` resolved (`country=="RO"`) → contains `country_code=RO`, `ieee80211d=1`, and the
    intended 5 GHz VHT80 block.
  - `pick_24_channel`: empty survey → 6; congested-6 survey → 1 or 11; tie-break lowest.
  - `next_rung_action`: Stable→Keep; WidthCollapsed@attempt0→RetrySameRung; WidthCollapsed at
    max_retries→StepDown; ChanspecFailStorm→RetrySame→StepDown; Down→RetrySame→StepDown;
    ClientFailed→StepDown.
  - `resolved_country_for_render` + `decide_country` ladders (already covered) stay green.
  - INVERT the three existing tests that assert `country_code=00` is emitted
    (`world_00_5ghz_ap_falls_back_to_24ghz_ht20_so_hostapd_starts`, `ap_band_24_hidden`,
    `country_auto_or_junk_is_sanitized_never_emitted`) to assert the line is now OMITTED.
- **T1 config-parse assertion (real hostapd dry-parse):** a CI step renders both confs and runs
  `hostapd -dd -t <conf>` (config-validate only, no radio): the unresolved conf MUST parse and MUST
  NOT contain `country_code=`; the resolved conf MUST contain `country_code=<CC>`. This is the
  regression gate for GAP-W2 — it fails if `country_code=00` ever reaches a generated conf.
- **T2 shell (shellcheck + bats):** `regdomain-apply.sh` re-resolve mode is idempotent (same CC →
  no restart; real→00 → no downgrade); the "only restart hostapd if CC changed" guard; the ordering
  `stop hostapd → iw reg set → reconcile`.
- **T3 systemd unit-ordering assertions (QEMU arm64 boot):** `systemd-analyze verify` +
  `systemctl list-dependencies` prove `hookprobe-regdomain Before hookprobe-network-reconcile`,
  `hookprobe-regdomain-reresolve After network-online.target`, hostapd `After hookprobe-regdomain`,
  and that `network-online.target` is reached (AP iface `RequiredForOnline=no`, so wait-online does
  not hang on wlan0). Assert NO generated `/etc/hostapd/*.conf` contains `country_code=00`.
- **Cannot validate without hardware (stated honestly):** the actual brcmfmac DFS bounce, whether a
  clean restart holds VHT80, GeoIP-from-real-ISP-IP end-to-end, and real 2.4 GHz survey congestion.
  The verify-retry LOGIC is nonetheless fully unit-testable via `verify_rung` + `next_rung_action`
  over synthetic `ObservedAp` inputs (the runtime only supplies the observations). A metal gate on a
  CM5/Pi5 remains the acceptance criterion for the radio-behaviour half.

## Extension 2026-07-13 (D15–D23) — adaptive 5GHz-FIRST AP band (operator directive: "always fight to get 5 GHz, 2.4 GHz only as fallback")

**Status of this extension:** 🟡 Proposed (os-architect). Design-complete + buildable; the *usability-signal thresholds* are marked "pending live CM5-5GHz diagnosis" where the exact root cause is still unconfirmed (candidates: the resolved regdomain marking the operating 5 GHz channel **No-IR** so the AP cannot beacon; or a brcmfmac AP-mode firmware quirk drifting the control channel ch36→ch40 into a non-beaconing state). The design catches BOTH by construction (D16) and is robust to whichever the live data confirms.

### Problem this closes (three defeaters of "5 GHz-first" found on metal)

1. **The shipped intent hard-pins `band: "2.4"`.** The pure ladder ([`candidate_ladder`]) already prefers 5 GHz, but the reconciler never reaches it because the operator-facing default forces 2.4. This is a *blunt always-joinable floor* — we replace it with an *adaptive* floor (D15/D22).
2. **The CM5 "hostapd-up-but-invisible-SSID" case is classified `Stable`.** On the CM5 the 5 GHz AP held ch40/80 at the radio level (iw stable, AP-ENABLED) yet no client could see the SSID. `verify_rung` returns `Stable` for it (channel/width match, no client expected → Stable) — the failure is INVISIBLE to today's signal, so the loop keeps a dead AP. D16 adds the missing no-client signals (No-IR channel flag + hostapd state-bounce + beacon liveness).
3. **The 2.4 floor is a constant ch6.** Two co-located boxes both land on ch6 (the Pi4 ~20 Mbps co-channel observation). D18 makes the floor device-derived {1,6,11}.

### D15 — Intent: `band: "auto"` is the new DEFAULT = 5 GHz-first with a guaranteed 2.4 floor

`ApIntent.band` gains a canonical value **`"auto"`** (and *absent* ⇒ `"auto"`). Semantics, decided (not enumerated):

- **`"auto"` (new default, and what every image ships):** the calibration loop OWNS band+channel+width. It fights for the best usable 5 GHz rung and steps down to the 2.4 floor **only** when 5 GHz is proven unusable on THIS radio+regdomain (D16/D20). The AP is ALWAYS left joinable (the 2.4/HT20 floor is a terminal Keep — D20).
- **`"5"` (hard pin, power-user):** 5 GHz rungs only; documented that this MAY leave the AP down on a radio/regdomain that cannot serve 5 GHz — an explicit operator override of the always-joinable default. Not recommended; `auto` is.
- **`"2.4"` (hard pin, legacy):** the old blunt floor, single-band. Kept for explicit use.

Rationale for ONE knob (not a separate `prefer:` field): capability/measurement-driven, minimal schema, and the outcome (5 GHz) is discovered, never declared — the AEGIS "config is a generated artifact" pattern. `"auto"` expresses the directive exactly: *fight for 5 GHz, fall back to 2.4 only when it can't serve.*

### D16 — The 5 GHz-usability signal (pre-flight No-IR gate + post-apply verdict), the heart of this extension

Two independent, radio-free-pure signals decide "5 GHz is usable here" WITHOUT needing a client. Ranked, most-decisive first:

**(a) Pre-flight — is any 5 GHz channel AP-CAPABLE in the resolved regdomain?** New pure input + fn in `wifi_calibrate.rs`:
```rust
pub struct ChannelFlags { pub channel: u32, pub no_ir: bool, pub radar_dfs: bool, pub disabled: bool }
/// AP-usable 5 GHz channels = reg.non_dfs_5ghz MINUS (no_ir | disabled | radar_dfs), in reg
/// preference order. EMPTY flags (iw unparsable) ⇒ return reg.non_dfs_5ghz UNCHANGED (optimistic:
/// never lock out 5 GHz just because we couldn't read flags; the post-apply verdict still catches
/// a real No-IR via ApDisabled/BeaconOnly).
pub fn ap_capable_5ghz(reg: &RegChannels, flags: &[ChannelFlags]) -> Vec<u32>
```
An AP **cannot beacon on a No-IR ("no initiating radiation") channel** — this is the single strongest candidate root cause of the CM5 invisible-SSID (a regdb entry marking UNII-1 No-IR/indoor-client-only). Source: `iw phy#<n> channels` per-frequency flags (`no IR`, `radar detection`, `disabled`). Gathered once by `regdomain-apply.sh` right AFTER `iw reg set` and written to `/run/hookprobe/wifi-5ghz-ap-capable` (a space-separated channel list) so render, reconcile, and calibrate share ONE parse (single source of truth, D21).

**(b) Post-apply — did hostapd reach AP-ENABLED AND STAY, on an AP-capable channel that matches the request?** Extend `ObservedAp` with three no-client fields:
```rust
pub hostapd_state_enabled: Option<bool>, // hostapd_cli status → state=ENABLED
pub oper_channel_no_ir:   Option<bool>, // is the channel it ACTUALLY settled on No-IR in the ACTIVE reg?
pub state_bounced:        bool,         // saw ENABLED→DISABLED in the settle window (the "beacon silently stops" signature)
```
Extend `Stability` with three variants and re-order `verify_rung` so the definitively-unusable cases win OVER the BUG-W5 "convergence-wins" rule (because the CM5 case IS converged-but-invisible — convergence alone must NOT be trusted for 5 GHz):
```
Down
  → ApDisabled      (state_bounced, or hostapd_state_enabled == Some(false))   // beacon stopped
  → NoIrUnusable    (oper_channel_no_ir == Some(true))                          // channel can't beacon, ever
  → (converged channel+width?) → ClientFailed | BeaconOnlySuspect | Stable
  → (not converged) → ChanspecFailStorm | WidthCollapsed
```
`BeaconOnlySuspect` (NEW, weak): AP-ENABLED + converged + AP-capable channel but a LONG grace (default 10 min) elapsed with 0 associations AND a corroborating weak signal (e.g. no probe requests seen). It is **recorded for telemetry, NOT an auto-step-down trigger at bring-up** — a genuinely empty AP is normal; we never abandon a good 5 GHz rung just because nobody has connected yet. It only *breaks a tie* toward 2.4 when the loop is already deciding between a marginal 5 GHz rung and the floor.

**Pluggability for the live diagnosis:** each candidate root cause is an INDEPENDENT signal — No-IR ⇒ `NoIrUnusable` (a), ch36→ch40 drift ⇒ existing channel-mismatch ⇒ `WidthCollapsed`, beacon-stops ⇒ `ApDisabled` (b). When the live CM5 data lands, we confirm WHICH fires and tune only its threshold; the state machine does not change.

### D17 — 5 GHz channel selection (deterministic, AP-safe, No-IR-aware, DFS-free)

```rust
/// Pick a 5 GHz primary for `width`, from ap_capable (D16a) ∩ reg preference, excluding channels
/// already tried this run. VHT80 requires the WHOLE 36-48 block AP-capable (primary 36); HT40 the
/// lowest AP-capable valid pair; HT20 the lowest AP-capable, with a per-device rotation offset from
/// device_id (two co-located boxes prefer different UNII-1 channels at HT20/HT40). None ⇒ no usable
/// 5 GHz channel → caller falls to the 2.4 floor. DFS (52-144) is NEVER selected — no radar-wait at
/// bring-up (unchanged policy).
pub fn pick_5ghz_channel(reg: &RegChannels, ap_capable: &[u32], exclude: &[u32],
                         width: ChanWidthShim, device_id: &str) -> Option<u32>
```
Composes with `candidate_ladder`: the 5 GHz rungs take their channel from `pick_5ghz_channel` instead of the hardcoded 36, and on a `NoIrUnusable`/`ApDisabled` verdict the runtime calls it again with the failed channel added to `exclude` (the RepickChannel action, D20). Note: at VHT80 there is only ONE non-overlapping UNII-1 block (36-48, center 42), so device de-confliction applies only at HT20/HT40 — VHT80 co-channel between two boxes is acceptable (far less harmful than 2.4 ch6 collision).

### D18 — 2.4 GHz co-channel de-confliction (device-derived 1/6/11)

The boot/no-survey 2.4 default becomes device-derived, not the constant 6:
```rust
/// Deterministic non-overlapping 2.4 GHz channel {1,6,11} from the signed manifest device_id
/// (same hash pattern as default_ssid) — two boxes flashed from one image pick different channels.
pub fn default_24_channel(device_id: &str) -> u32
```
`pick_24_channel(survey)` keeps the runtime survey path (real congestion wins), but its **tie-break changes from "lowest channel" to the device-derived order**, and the boot path (empty survey) returns `default_24_channel(device_id)` instead of `6`. `wifi_cfg::render_ap`'s world-`00` fail-safe channel changes from `pick_24_channel(&[])` (constant 6) to `default_24_channel(device_id)` — this threads `device_id` into `render_ap` (internal signature change; `render()` already has it).

### D19 — Band-outcome memory (LKG-band), distinct from the regdomain-LKG

New compact boot-fast-path artifact `/var/lib/hookprobe/wifi-band-lkg-<iface>.json`, DISTINCT from `/var/lib/hookprobe/regdomain-lkg` (which is country-only):
```rust
pub struct BandLkg { pub cc: String, pub radio_id: String, pub band: String,
                     pub label: String, pub channel: u32, pub decided_at: String }
/// Valid only when the CURRENT regdomain AND radio still match — a moved box (new CC → different
/// No-IR flags) or a swapped radio re-fights from the top.
pub fn band_lkg_valid(lkg: &BandLkg, cc: &str, radio_id: &str) -> bool
```
Written by the calibrate loop on a Keep (the winning rung). `label` IS the `start_rung(ladder, cached_label)` input already present — so next boot starts on the PROVEN rung with NO flap and NO wasted 5 GHz attempt on a known-bad radio. `radio_id` = a stable radio fingerprint (phy MAC / driver+vendor, from the manifest `wifi_radios`). `wifi-calibration.json` stays the verbose evidence artifact (D9); band-LKG is its boot-consulted extract.

### D20 — The extended fallback state machine (2-D: channel × width, then band; floor is terminal)

`RungAction` gains **`RepickChannel`**; the action fn takes a repick budget (single-source; the shell mirror + ~5 unit tests update with it — honest, not a parallel copy):
```rust
pub enum RungAction { Keep, RetrySameRung, RepickChannel, StepDown }
pub fn next_rung_action(v: Stability, attempt_on_rung: u32, max_retries: u32,
                        repicks_used: u32, max_repicks: u32) -> RungAction
```
Loop (runtime, `wifi-calibrate.sh` + the future `--wifi-calibrate` subcommand):
```
START rung:
  band-LKG valid?                       → start at LKG rung (band+channel+width), no flap
  else ap_capable_5ghz nonempty?        → 5 GHz top rung (fight for it, D15/D16a)
  else                                  → 2.4 floor
LOOP over rungs (best→safe within band, then band step-down):
  pre-flight: 5 GHz rung whose channel ∉ ap_capable → RepickChannel (or → 2.4 if none)
  apply (render + clean_restart) · settle · observe · verify_rung → verdict
  next_rung_action(verdict, attempt, max_retries=2, repicks_used, max_repicks=#ap_capable):
    Stable                                   → Keep   (write band-LKG, DONE)
    WidthCollapsed|ChanspecFailStorm|Down    → RetrySameRung (≤2, transient bounce) then StepDown(width)
    NoIrUnusable|ApDisabled                  → RepickChannel (next AP-capable ch, NO same-ch retry — futile) then StepDown(width→band)
    ClientFailed                             → StepDown        (no retry burn)
    BeaconOnlySuspect                        → Keep at bring-up (telemetry only); tie-breaks toward 2.4 only vs a marginal rung
  width step-down: VHT80 → HT40 → HT20  (same band)
  5 GHz exhausted / no AP-capable ch    → band step-down → 2.4
  2.4: HT40 (if reg allows) → HT20 FLOOR
FLOOR (2.4/HT20, device-derived channel): TERMINAL — always Keep, NEVER step below.
```
This upholds the customer-first invariant absolutely: the 2.4/HT20 floor on a device-derived non-overlapping channel is the most-reliable config that exists and is accepted unconditionally — the AP is NEVER left down. Total bring-up is bounded: ≤2 same-rung retries per width × 3 widths + ≤#ap_capable channel re-picks, then the floor.

### D21 — Runtime signal sources (for code-developer; the pure core stays radio-free)

- **No-IR / AP-capable channels:** `iw phy#<n> channels` flags → parsed by `regdomain-apply.sh` post-`iw reg set` → `/run/hookprobe/wifi-5ghz-ap-capable`. Calibrate re-reads it (and re-parses post-apply for the operating channel as belt-and-suspenders → `oper_channel_no_ir`).
- **hostapd state + operating chanspec:** `hostapd_cli -i <iface> status` (`state=ENABLED`, `channel=`, `secondary_channel=`, `vht_oper_chwidth=`, `beacon_int=`); fall back to `iw dev <iface> info` + scanning the hostapd journal for `AP-ENABLED`/`AP-DISABLED`/`interface state ENABLED->DISABLED` (→ `state_bounced`).
- **Weak grace / BeaconOnlySuspect:** `iw dev <iface> station dump` count over the long grace; recorded, not enforced at bring-up.

### D22 — Migration from the `band: "2.4"` default

- `base/config/network.example.yaml` and BOTH `builder/mkosi{,-arm64}/mkosi.extra/etc/hookprobe/network.yaml`: `band: "2.4"` → `band: "auto"`, with a rewritten comment: *"auto = fight for 5 GHz, fall back to 2.4 only if this radio+regdomain can't serve it; the AP always ends joinable. The old `band: 5`/`2.4` hard pins remain for power users."* The obsolete "set band:5 only on verified-reliable hardware" note is deleted — the box now discovers reliability itself.
- Supervisor reconcile resolves the bootstrap band BEFORE `render_ap` (keeps `wifi_cfg` pure):
```rust
/// "5"|"2.4" bootstrap band for the FIRST hostapd conf (calibrate then converges). Honors hard
/// pins; for auto uses band-LKG if valid, else 5 GHz when a 5 GHz channel is AP-capable, else 2.4.
pub fn resolve_bootstrap_band(intent_band: Option<&str>, band_lkg: Option<&BandLkg>,
                              ap_capable_5ghz_present: bool) -> &'static str
```
`effective_band("auto")` still maps to `"2.4"` as a last-ditch (never rendered directly under the new flow, since reconcile passes a resolved "5"/"2.4").

### D23 — Tests + gates (T1 pure; T3 QEMU ordering; metal gate pending live CM5)

New/changed unit tests (`wifi_calibrate.rs` + `wifi_cfg.rs`): `ap_capable_5ghz` (No-IR/DFS/disabled filter; empty-flags optimism); `pick_5ghz_channel` (deterministic lowest AP-capable, VHT80 whole-block rule, exclude, device rotation, None→floor); `default_24_channel` (device→{1,6,11}, two devices differ); `verify_rung` new variants (`NoIrUnusable` beats convergence — the CM5 case; `ApDisabled` on state-bounce; `BeaconOnlySuspect` recorded-not-enforced); `next_rung_action` `RepickChannel` budget then `StepDown`; `resolve_bootstrap_band`; `band_lkg_valid` (CC/radio change invalidates). The shell `wifi-calibrate.sh` LADDER becomes channel-parameterized with the No-IR pre-flight + `hostapd_cli` state read, mirroring the Rust actions. **Metal gate (acceptance):** the live CM5-5GHz diagnosis confirms which signal fires; a CM5/Pi5 boot proves the loop converges to the best usable band unattended and NEVER leaves the AP down.

## Extension 2026-07-15 (D24–D33) — the AUTONOMOUS survey-based 5 GHz channel optimizer (operator directive: "scan at 3AM, find the least-congested channel per ETSI EN 301 893, self-validate, else default to ch40")

**Status of this extension:** 🟡 Proposed (os-architect). Design-complete; the *pure core* (candidate
enumeration, scoring, select/hysteresis, DFS-support learning, LKG/precedence, artifact) is fully
unit-testable and specified below for code-developer to implement AFTER the current 3-rung ladder
fix (D6, revised 2026-07-15) lands. The *radio-behaviour half* (does brcmfmac actually run DFS CAC +
beacon in AP mode; is a DFS block really cleaner on a given site) is **test-and-fallback by
construction** — the optimizer never trusts DFS, it PROVES it per (radio, regdomain) and degrades to
the ch40 anchor otherwise. Metal gate on a CM5/Pi5 remains the acceptance criterion.

### The load-bearing insight that shapes this whole extension

In every ETSI (RO/EU/GB) domain there is **exactly ONE non-DFS 80 MHz block: 36–48 (center idx 42,
control ch40, 23 dBm indoor)** — which is therefore the single most-congested VHT80 option. Every
*other* VHT80 block that ETSI EN 301 893 permits (52–64/center58, 100–112/center106, 116–128/center122
meteo, 132–144/center138) is **DFS**. Consequence: **a meaningfully-cleaner VHT80 channel than ch40 is
almost always a DFS channel.** So this optimizer is, in practice, "safely reach a DFS block when it is
both *supported by this radio* and *materially cleaner*, else stay on the proven non-DFS ch40 anchor."
This is exactly why it must sit ABOVE the boot ladder (which stays deliberately DFS-free and fast) and
never inside it.

### D24 — Scope, layering, and the strict precedence chain (boot stays fast + DFS-free; the optimizer is a separate, scheduled, opt-in layer)

The boot calibrate ladder (D6, D14, D20) is **unchanged and authoritative for bring-up**: it comes up
FAST on the proven non-DFS anchor (5GHz-VHT80-ch40 → HT40-ch36 → 2.4 floor), never runs a DFS CAC, and
never waits for 3 AM. The optimizer is a **strictly-additive layer** that only ever runs on its own
schedule / on-demand / on-regdomain-change, is **off the enforcement path** (it touches the AP radio
only), and **can only ever hand the AP a channel it has already validated** — on any failure it hands
back the exact channel the ladder would have chosen (ch40). It NEVER blocks boot, NEVER runs at bring-up,
and NEVER leaves the AP down.

**Precedence the reconciler resolves for the operating 5 GHz channel (highest wins):**

| Prio | Source | Where | Notes |
|---|---|---|---|
| 1 | **Operator hard-pin** `wifi.ap.channel: 100` | intent | ALWAYS wins; disables the optimizer's channel authority (it may still record scores as advisory). A pinned DFS channel is still CAC-validated, and still reverts to ch40 if it cannot hold — the always-joinable invariant outranks even a pin. |
| 2 | **channel-LKG** (`wifi-channel-lkg-<iface>.json`, D31) | persisted | The last channel the optimizer VALIDATED and committed. Applied at boot ONLY if non-DFS (fast); a DFS channel-LKG is restored post-boot by the reapply path (D30), never blocking bring-up. |
| 3 | **Boot default** ch40 (the D6 ladder top) | code | The universal non-DFS anchor. Every optimizer failure path terminates here. |

**The optimizer can only move prio-2; it can never override a prio-1 pin, and a failed optimization
always degrades to prio-3, never to a dead AP.**

### D25 — Scheduling (systemd timer, 03:00 daily, intent-configurable; plus on-demand + on-regdomain-change)

- **Unit:** `hookprobe-wifi-optimize@<iface>.service` (`Type=oneshot`, same privilege/slice posture as
  `hookprobe-wifi-calibrate@` — `CAP_NET_ADMIN CAP_NET_RAW`, `hookprobe-dataplane.slice`,
  `ReadWritePaths=-/etc/hostapd -/var/lib/hookprobe -/run`). `ExecStart=/usr/lib/hookprobe/wifi-optimize.sh %i optimize`.
- **Timer:** `hookprobe-wifi-optimize@<iface>.timer` → `OnCalendar=*-*-* 03:00:00`, `Persistent=false`
  (a missed run is NOT run late during busy daytime — it waits for the next 03:00), `RandomizedDelaySec=1800`
  (jitter 0–30 min so a fleet flashed from one image does not survey in lockstep). The interface + time
  are rendered by the reconciler from intent; a disabled optimizer masks the timer.
- **Triggers, all routing through the same script/subcommand:** (1) the daily timer → `optimize` mode
  (full survey→score→select→validate→commit/revert); (2) on-demand `systemctl start
  hookprobe-wifi-optimize@wlan0` (operator/Mission Control button) → `optimize`; (3) on-regdomain-change
  — the existing `hookprobe-regdomain-reresolve` path, when it commits a NEW CC, additionally `systemctl
  start`s the optimizer (a new CC = new legal channel set + invalidated LKG, D31) → `optimize`; (4)
  post-boot DFS-LKG restore (D30) → `reapply` mode. `optimize` is **off** the enforcement path and never
  auto-fires from packet-plane events.
- **Intent schema (network.yaml), new nested block under the existing `wifi.ap`:**
  ```yaml
  wifi:
    ap:
      band: auto              # (D15) unchanged
      # channel: 100          # (D24 prio-1) optional operator hard-pin; disables optimizer channel authority
      optimize:
        enabled: true         # default true when band is 5/auto with a 5GHz-capable radio; false pins to boot anchor
        at: "03:00"           # local time; -> OnCalendar; "off"/absent with enabled:false masks the timer
        allow_dfs: true       # default true = MAY use DFS blocks IF the radio proves it can (D27/D30); false = non-DFS-only (optimizer then almost always Keeps ch40)
        allow_meteo: false    # default false = the 5600-5650 MHz 10-min-CAC sub-band (ch116-128) is disfavored to near-exclusion (D28); true only for a fixed indoor deployment that wants it
        min_improvement: 20   # (D28) required busy-% improvement over the current channel to switch (hysteresis)
  ```
  Pure resolver `optimize_intent(&ApIntent) -> OptimizeConfig` in `wifi_calibrate.rs` (unit-tested;
  absent block ⇒ the defaults above; `band: "2.4"` hard-pin ⇒ optimizer disabled — nothing to optimize).

### D26 — Congestion measurement with ONE FullMAC radio (survey dump on-channel + off-channel scan; busy-time primary, BSS-count fallback)

No second radio exists, so the optimizer measures in two complementary ways, decided (not enumerated):

1. **On-channel occupancy — `iw dev <ap> survey dump` (PRIMARY metric).** Yields per-frequency
   `channel active time` + `channel busy time` (+ noise floor). `busy_ratio = busy/active × 100` is the
   truest congestion signal — it captures ALL energy (hidden nodes, non-Wi-Fi interferers), not just
   decodable beacons. But a FullMAC radio only reports it for the channel it is CURRENTLY on.
2. **Off-channel neighbour density — `iw dev <ap> scan` (FALLBACK / corroborating metric).** A single
   scan visits every channel and returns the BSS list; `bss_count[chan]` (with signal, weighted so a
   strong neighbour counts more) is a good *relative* congestion proxy for channels the radio is NOT
   sitting on. It misses non-Wi-Fi energy but needs no channel dwell.

**Method (decisive):** the optimizer does a **single full `iw scan`** to get `bss_count` for every
candidate block, PLUS a **`survey dump` on the current operating channel** for its true `busy_ratio`.
For the *candidate* channels it is not on, it optionally does a **brief off-channel visit** — momentarily
retune the radio (AP briefly down for the visited channel's dwell) to pull a `survey dump` sample — ONLY
for the top 1–2 scan-ranked candidates, bounded to a **≤2 s total off-channel budget** (D28 disruption
budget), never a sweep of all blocks. **hostapd ACS (`channel=acs`/`acs_survey`) is NOT relied upon** —
brcmfmac ACS support is doubtful; the manual `iw scan` + targeted `survey dump` is the specified
fallback and the default path. If the radio refuses off-channel survey, the optimizer scores purely on
`bss_count` (the `busy_ratio` term drops out for candidates, kept only for the current channel) — a
graceful, capability-driven degradation, never a hardware branch.

New pure struct (extends the existing `ChannelSurvey`, D13, which stays the 2.4 GHz shape):
```rust
pub struct BlockSurvey {           // one VHT80 candidate block's measured load
    pub control_channel: u32,      // block anchor / hostapd `channel=` (36/52/100/116/132)
    pub center_idx: u32,           // vht_oper_centr_freq_seg0_idx (42/58/106/122/138)
    pub busy_ratio: Option<u8>,    // 0-100 from on/off-channel survey dump; None if not surveyed (scan-only)
    pub bss_count: u32,            // weighted neighbour BSS count across the block's 4 x 20 MHz from `iw scan`
    pub noise_dbm: Option<i32>,    // survey noise floor, tie-break only
    pub dfs: bool,                 // is_dfs_rung(control_channel, 80)
    pub cac_seconds: u32,          // dfs_cac_seconds(control_channel, 80): 0 / 60 / 600
    pub max_eirp_dbm: u32,         // 23 (UNII-1) or 30 (the 100-144 DFS blocks) - from reg
    pub ap_capable: bool,          // /run/hookprobe/wifi-5ghz-ap-capable (No-IR/disabled filter, D16a) AND DFS-support not blocklisted (D30)
}
```

### D27 — Candidate set (ETSI EN 301 893 + capability-aware; this REVISES D4/D6's blanket DFS exclusion, for the OPTIMIZER ONLY)

The boot ladder's DFS exclusion (D4/D6: "an unattended edge AP must not gamble on radar CAC *at
bring-up*") is correct **for bring-up** and stays. The optimizer runs at 3 AM, can afford a 60 s CAC, and
**tests DFS before trusting it** — so it is the right and only place DFS becomes admissible. New pure fn
`optimize_candidates(reg, caps, flags, state, cfg) -> Vec<BlockSurvey-skeleton>` enumerates the VHT80
blocks legal in the resolved regdomain AND advertised by the radio (`iw phy channels` per-freq flags),
from this ETSI EN 301 893 table (the authoritative source of block geometry, disfavour weights, and CAC):

| Block | Control | center_idx | DFS | Max EIRP | CAC | Admit when |
|---|---|---|---|---|---|---|
| UNII-1 36–48 | 40 | 42 | no | 23 dBm | 0 s | ALWAYS (the anchor; the reference the others must beat) |
| UNII-2A 52–64 | 52 | 58 | yes | 23 dBm | 60 s | `allow_dfs` AND radio advertises + not blocklisted (D30) |
| UNII-2C 100–112 | 100 | 106 | yes | **30 dBm** | 60 s | as above — usually the CLEANEST + highest power → the prime target |
| UNII-2C 116–128 | 116 | 122 | yes | **30 dBm** | **600 s (meteo)** | `allow_dfs` AND `allow_meteo` (default false) — strongly disfavoured (D28) |
| UNII-2C 132–144 | 132 | 138 | yes | 30 dBm | 60 s | `allow_dfs` AND radio supports **ch144** (many chipsets disable it → the block is dropped if 144 absent from `iw phy`) |

FCC-style domains (D4) additionally keep the non-DFS UNII-3 149–161 block. The world `00` domain gets
UNII-1 only (optimizer effectively a no-op → always Keeps ch40). **Candidate geometry, disfavour, and
CAC come from this table; final legality is still the kernel `wireless-regdb` (a block the regdb marks
No-IR/disabled is filtered by `ap_capable`, D16a) — the table only proposes, the regdb + the live
validation dispose.**

### D28 — Scoring, weighting, and hysteresis (congestion primary; EIRP + CAC secondary; a strong bias to STAY)

Lower score = better (a cost). Pure, unit-tested:
```rust
pub struct OptimizeWeights {                 // defaults in code, not intent (tuned, not operated)
    pub w_busy: i32,            //   4  per 1% channel-busy time (PRIMARY — the survey signal)
    pub w_bss:  i32,            //   3  per weighted neighbour BSS (fallback/corroborating)
    pub eirp_bonus_per_db: i32, //  -6  per dBm of max-EIRP above the 23 dBm UNII-1 floor (range/SNR headroom)
    pub cac_penalty_std: i32,   //  40  flat, a 60 s-CAC DFS block (one-off 60 s client outage to adopt it)
    pub cac_penalty_meteo: i32, // 400  flat, the 600 s meteo block — near-exclusion unless dramatically cleaner
    pub switch_margin: i32,     //  30  the candidate must beat the CURRENT channel's score by THIS to switch (hysteresis)
    pub quiet_floor_busy: u8,   //  20  if the current channel's busy_ratio < this, DON'T switch at all (already fine)
}
pub fn score_block(b: &BlockSurvey, w: &OptimizeWeights) -> i32
// = w.w_busy*busy_ratio(or a bss-derived estimate when busy is None)
//   + w.w_bss*bss_count
//   + w.eirp_bonus_per_db*(max_eirp_dbm - 23)          // negative term: more power lowers cost
//   + (dfs ? (meteo ? cac_penalty_meteo : cac_penalty_std) : 0)
```
`min_improvement` from intent maps into `switch_margin` (default 20% busy ≈ 30 score points at
`w_busy=4` plus the BSS term). **Two hysteresis gates BOTH must pass to switch:** (1) current channel
busy ≥ `quiet_floor_busy` (don't disrupt a working quiet AP for a marginal gain), AND (2)
`score(best_candidate) + switch_margin ≤ score(current)` (meaningfully, not marginally, better). The
+EIRP bonus is what lets a clean 30 dBm UNII-2C block win over a congested 23 dBm ch40; the CAC penalty
is what keeps the optimizer from chasing a DFS block that is only slightly cleaner (not worth a 60 s
outage) and all-but-forbids the 600 s meteo block. **Max-disruption budget: at most ONE channel switch
attempt per run** — the single best-scoring candidate that clears both gates. If it fails validation
(D29), REVERT and do not try the next candidate this run (bounded to ~one client-visible bounce per
night); the failure is recorded so the next run's candidate set already excludes it (D30).

### D29 — The survey → score → select → validate → commit/revert state machine (the heart; every path ends on a validated working channel)

Pure decision: `select_optimized_channel(current: &BlockSurvey, cands: &[BlockSurvey], w) ->
OptimizeDecision` where
```rust
pub enum OptimizeDecision { Keep { reason: String }, Switch { to: BlockSurvey, reason: String } }
```
Runtime (`wifi-optimize.sh <iface> optimize`, mirrored by the future `hookprobe-supervisor
--wifi-optimize` subcommand routing through the pure core):
```
0. GUARDS: optimizer enabled? band ∈ {5,auto}? radio 5GHz-capable? NOT operator-pinned (prio-1)?
   else EXIT (log skip reason). Read current operating block via `iw dev <ap> info` + `survey dump`.
1. MEASURE (D26): one full `iw scan` → bss_count per block; `survey dump` on the current channel;
   targeted off-channel survey for the top 1-2 scan-ranked candidates within the ≤2 s budget.
2. ENUMERATE (D27) + SCORE (D28) every candidate + the current channel.
3. SELECT: select_optimized_channel → 
     Keep    → write artifact, DONE (this is the common nightly result: ch40 stays or a prior DFS-LKG stays).
     Switch{to} → proceed to VALIDATE.
4. VALIDATE the chosen candidate (the SAME verify contract the calibrate loop uses, DFS-aware):
     a. render a DFS-AWARE hostapd conf for `to` (VHT80, center_idx, and — only for a DFS block —
        `ieee80211h=1` so the kernel runs CAC; a FullMAC that REJECTS ieee80211h → hostapd exits →
        verdict Down at step d = the DFS-unsupported test result, D30).
     b. clean_restart (stop → ensure no supplicant/scan on the AP radio, per D5 → start) on `to`.
     c. if DFS: WAIT the correct CAC via `select_settle_seconds` (60 s standard / 600 s meteo) — a
        `state=DFS`/`DFS-CAC-START..COMPLETED` window is EXPECTED, NOT a failure. A CAC that never
        completes within `cac_seconds + settle` → RevertedCacTimeout.
     d. OBSERVE (`hostapd_cli status` + `iw dev info` + dmesg) and reuse `verify_rung` (D7/D16):
        Stable (AP-ENABLED, oper channel+width == requested, no state-bounce, on an AP-capable
        non-No-IR channel) AND — where a client is present — a reachability sanity check (a station
        that was associated before the switch re-associates, or a self-probe succeeds).
     e. VERDICT:
          Stable + reachable  → COMMIT: persist channel-LKG (D31), write artifact, DONE.
          anything else       → REVERT (below), record the failure (D30).
5. REVERT (the always-joinable guarantee, ordered): restore the PREVIOUS working channel
   (the current block from step 0) via clean_restart; if THAT no longer holds → fall to the boot
   default **VHT80-ch40**; if ch40 itself won't hold → hand off to the D20 calibrate ladder (HT40 →
   2.4 floor). The AP is NEVER left down — every revert branch terminates on a validated, joinable
   channel, exactly as the boot ladder guarantees.
```
`OptimizeVerify` variants recorded in the artifact: `Committed`, `KeptNotBetter`, `RevertedFailedToHold`,
`RevertedCacTimeout`, `RevertedNotReachable`. Total worst-case client disruption per run is bounded: one
scan + a ≤2 s off-channel survey + at most one switch (≤ one CAC wait) + at most one revert.

### D30 — DFS is TESTED, then LEARNED (per radio + regdomain); brcmfmac DFS uncertainty handled by construction

The FullMAC DFS-AP uncertainty is resolved empirically and remembered, so a radio that cannot do DFS is
disrupted **at most once, ever** (until its radio or regdomain changes):
- The FIRST time the optimizer tries any DFS block, step 4 IS the DFS-support test. `Down` (hostapd
  rejected `ieee80211h`/DFS) or `RevertedCacTimeout` (firmware never completes CAC) → set
  `dfs_ap_supported = false` in the optimize-state cache; thereafter the optimizer proposes NON-DFS
  candidates only → it Keeps ch40 forever on that radio, never re-attempting (no repeat nightly
  disruption). A `Stable` DFS commit → `dfs_ap_supported = true`.
- A specific DFS block that reaches AP-ENABLED but won't HOLD (bounces, or radar-detected → hostapd
  vacates) is added to `blocked_channels` (channel-specific, not a whole-DFS ban) so the next run's
  candidate set excludes just it. A real `radar detected` event during operation (`iw`/hostapd
  `DFS-RADAR-DETECTED`) is honoured immediately: vacate per regulation and revert to ch40 (compliance
  outranks optimization — the ADR 0023 "compliance-as-safety" line).
```rust
pub struct OptimizeState {                    // /var/lib/hookprobe/wifi-optimize-state-<iface>.json
    pub cc: String, pub radio_id: String,
    pub dfs_ap_supported: Option<bool>,       // None untested · false proven-unsupported (stop trying) · true works
    pub blocked_channels: Vec<u32>,           // specific DFS blocks that failed to hold
    pub current_channel: u32, pub current_score: i32, pub last_run: String,
}
pub fn optimize_state_valid(s: &OptimizeState, cc: &str, radio_id: &str) -> bool  // CC/radio change ⇒ re-test DFS
```
This is the "detect once, query forever" pattern applied to a radio capability that `iw phy` cannot
honestly report (advertised DFS flag ≠ FullMAC-AP-mode DFS works).

### D31 — Persistence: the channel-LKG (survives reboot; feeds precedence D24)

The committed winner is persisted DISTINCT from the regdomain-LKG (country) and the band-LKG (D19,
rung/band):
```rust
pub struct ChannelLkg {                       // /var/lib/hookprobe/wifi-channel-lkg-<iface>.json
    pub cc: String, pub radio_id: String,
    pub control_channel: u32, pub center_idx: u32, pub width_mhz: u32,
    pub dfs: bool, pub score: i32, pub validated_at: String,
}
pub fn channel_lkg_valid(lkg: &ChannelLkg, cc: &str, radio_id: &str) -> bool  // CC or radio change ⇒ invalid, re-optimize
```
Precedence (D24) reads it via `resolve_operating_channel(intent_pin, channel_lkg, band_lkg) -> ChannelPlan`
where a `ChannelPlan { channel, center_idx, width, dfs, apply_at: BootFast | PostBootReapply }`. A
**non-DFS** channel-LKG (i.e. ch40 — the common case) is `BootFast`: the D6 ladder simply uses it as its
top channel, zero added boot latency. A **DFS** channel-LKG is `PostBootReapply`: the box boots FAST on
ch40 (never a boot-time CAC) and `network-apply.sh` starts `hookprobe-wifi-optimize@<iface>.service
reapply` shortly after hostapd — `reapply` SKIPS the survey/scoring and goes straight to step 4 (validate
the LKG DFS channel, with its CAC); on success it silently upgrades ch40 → the DFS channel within one CAC
window of boot, on any failure it stays on ch40 and clears the now-disproven LKG. So a reboot restores an
optimized DFS channel **without** waiting for 3 AM and **without** ever risking a slow or dead boot.

### D32 — Observability artifact (the evidence-graph / Mission Control surface)

`OptimizeOutcome::to_json()` → `/var/lib/hookprobe/wifi-channel-optimize.json` (sibling of
`wifi-calibration.json`, D9):
```rust
pub struct CandidateScore { pub label: String, pub control_channel: u32, pub center_idx: u32,
    pub busy_ratio: Option<u8>, pub bss_count: u32, pub max_eirp_dbm: u32, pub dfs: bool,
    pub cac_seconds: u32, pub score: i32, pub admitted: bool, pub reject_reason: Option<String> }
pub struct OptimizeOutcome {
    pub iface: String, pub trigger: String,        // "timer" | "on_demand" | "regdomain_change" | "reapply"
    pub cc: String, pub radio_id: String,
    pub current_before: CandidateScore,
    pub candidates: Vec<CandidateScore>,           // every enumerated block, scored, admitted-or-why-not
    pub decision: String,                          // "keep" | "switch"
    pub chosen: Option<CandidateScore>,
    pub verify: String,                            // OptimizeVerify variant
    pub committed_channel: u32,                    // what the AP ACTUALLY ended on (ch40 on any revert)
    pub dfs_ap_supported: Option<bool>,            // learned (D30)
    pub decided_at: String,
}
```
Every candidate carries WHY it was chosen or rejected (No-IR, DFS-unsupported, blocked, not-cleaner,
meteo-disfavoured, CAC-timeout). This is the "AI explanation panel everywhere / why · confidence ·
evidence" surface for the Wi-Fi radio in Mission Control (Observe/Administration), and telemetry-analyst's
per-platform truth of which DFS blocks a given radio really holds.

### D33 — Interaction with the boot ladder + band-LKG (no conflict; clean ownership)

- **Boot** owns bring-up: D6 ladder + band-LKG (D19) decide band+width+the *anchor* channel; a valid
  non-DFS channel-LKG only substitutes the top-rung CHANNEL (still ch40 in ETSI). Boot NEVER runs a
  survey or a CAC.
- **The optimizer** owns nothing at boot; it only ever runs on the D25 triggers, and its output is the
  channel-LKG the NEXT boot consults. band-LKG (band/width/rung) and channel-LKG (which 5 GHz channel
  within the chosen band+width) are orthogonal and both consulted: band-LKG answers "5 GHz VHT80 or step
  down?", channel-LKG answers "which VHT80 block?". A regdomain change invalidates BOTH (new legal set)
  and re-fires the full optimize.
- **A failed optimization degrades to the boot default, never a dead AP** (D29 revert chain) — the same
  always-joinable invariant the whole ADR upholds, now extended to the scheduled optimizer: the optimizer
  can only ever IMPROVE on ch40 or leave you exactly where the boot ladder would.

### D34 (extension tests + gates)

- **T1 pure (`wifi_calibrate.rs`):** `optimize_intent` (defaults; disabled on 2.4-pin);
  `optimize_candidates` (ETSI table membership; DFS gated by `allow_dfs`; meteo gated by `allow_meteo`;
  ch144 drop when absent; No-IR/blocklist filtered); `score_block` (busy dominates; +EIRP lowers a clean
  DFS block below a congested ch40; meteo penalty near-excludes; scan-only `busy=None` degradation);
  `select_optimized_channel` (Keep when current busy < quiet_floor; Keep when not better by margin; Switch
  only when both hysteresis gates pass; single best candidate); `optimize_state_valid`/`channel_lkg_valid`
  (CC/radio change invalidates → re-test); `resolve_operating_channel` (pin > channel-LKG > ch40; DFS-LKG ⇒
  PostBootReapply, non-DFS ⇒ BootFast); `OptimizeOutcome::to_json` round-trips.
- **T2 shell (shellcheck + bats):** `wifi-optimize.sh` `optimize` vs `reapply` modes; the ≤2 s
  off-channel budget; DFS CAC-wait uses `select_settle_seconds`; the REVERT chain lands on ch40 when the
  chosen channel is force-failed; idempotent Keep (no restart when decision=keep).
- **T3 QEMU arm64 ordering:** `hookprobe-wifi-optimize@.timer` `OnCalendar=03:00` present + masked when
  intent disables it; the service `After` network-online + hostapd; `systemd-analyze verify` 0 cycles; the
  timer NEVER on the boot critical path (does not gate `multi-user.target`).
- **Metal gate (acceptance, CM5/Pi5):** on a real brcmfmac — does a DFS block reach AP-ENABLED after CAC
  (learn `dfs_ap_supported`); does a committed DFS channel survive reboot via the reapply path within one
  CAC; does a force-failed DFS validation cleanly revert to ch40 with no dead-AP window; is the 03:00 run
  genuinely non-disruptive to an idle AP (Keep path = no restart). Honest limit: the actual per-site
  congestion delta and real radar events cannot be reproduced off-metal.

## Extension 2026-07-15b (D35–D44) — the Wi-Fi calibration LEARNING MODEL (one accumulating knowledge store that SUBSUMES band-LKG + channel-LKG + blocked_channels/dfs_ap_supported)

**Status of this extension:** 🟡 Proposed (os-architect). Design-complete; the pure core (the store,
the update rule, quality/confidence, direct-to-best selection, known-bad/decay, explore/exploit,
the artifact) is fully unit-testable and specified below for code-developer to implement. It reuses
every existing seam (`Rung`, `verify_rung`, `Stability`, `RegChannels`, `RadioCaps`,
`BlockSurvey`/`score_block`, `select_settle_seconds`, the D25 timer, the D29 validate/commit/revert
loop) and CHANGES NONE of them — it is a layer that sits ABOVE the boot ladder and the optimizer and
feeds off the outcomes they already produce. Metal gate on a CM5/Pi5 remains the acceptance criterion.

**Numbering note:** `D34` is already the optimizer's tests/gates section above; this extension
continues at **D35** (the operator brief's "D34+"). No prior decision is reopened — D6/D14/D20/D24
stay authoritative for bring-up and precedence; this extension only makes the *memory* accumulate
instead of remembering the last outcome.

### The operator directive this closes (verbatim)

> "Every calibration must have a learning and improvement curve, ML-like structure that does not
> repeat the same calibration twice and gets DIRECTLY to the channel and bandwidth — make it really
> smart."

### The one insight that shapes the whole extension

Today there are **three separate last-only caches** with overlapping keys, each remembering only the
*most recent* outcome: `BandLkg` (D19 — last-good rung), the spec-only `ChannelLkg` (D31 — last
validated 5 GHz channel), and the spec-only `OptimizeState.{dfs_ap_supported, blocked_channels}`
(D30 — a boolean bad-list + a boolean DFS-works flag). Each is a **projection of one richer object**:
a table keyed by the context that actually determines outcome — **(radio_id, regdomain, channel,
width)** — that *accumulates* per-config statistics. Replace the three caches with that ONE store and
every requirement (direct-to-best, never-repeat-known-bad, an improvement curve) falls out as a query
over it. This is "detect once, query forever" applied to *radio behaviour that `iw phy` cannot
honestly report* (advertised caps ≠ what holds in AP mode on THIS firmware, in THIS RF environment).

**This is NOT a neural net and has no training pipeline.** It is a bounded conjugate-Bayesian +
EMA table with online incremental updates — deterministic, auditable, ~9 KB, an O(≤64) table scan
per decision. The "ML-like structure" the operator wants is a **contextual bandit** (Beta-Bernoulli
for the binary "did it hold?" signal, EMA for the continuous congestion/throughput signals, a UCB
exploration bonus for the improvement curve). Every number the model acts on is human-readable and
carries its own "why."

### D35 — The knowledge store: schema, path, bound, eviction, and what it subsumes

`crates/hookprobe-manifest/src/wifi_calibrate.rs`, pure (no I/O; the runtime reads/writes the JSON):

```rust
pub const WIFI_LEARN_SCHEMA: u32 = 1;
pub const MAX_LEARN_ENTRIES: usize = 64;   // hard bound: ~17 legal configs/regdomain × a few visited domains

/// The context that DETERMINES a calibration outcome. Two configs with the same key are the "same
/// calibration"; the operator's "does not repeat the same calibration twice" is literally
/// "never re-probe a high-confidence key." radio_id + regdomain are the coarse context; channel +
/// width_mhz the fine one. (center_idx is NOT in the key — it is a deterministic function of
/// channel+width via `vht80_params`, carried on the stat for render only.)
pub struct ConfigKey { pub radio_id: String, pub regdomain: String, pub channel: u32, pub width_mhz: u32 }

/// One accumulating cell of knowledge for one ConfigKey.
pub struct ConfigStat {
    pub key: ConfigKey,
    pub center_idx: u32,          // vht_oper_centr_freq_seg0_idx for render; 0 for HT20/HT40-2.4
    pub band: String,             // "5" | "2.4" (echoed; derivable from channel)
    pub dfs: bool,                // is_dfs_rung(channel,width_mhz) — cached
    pub cac_seconds: u32,         // dfs_cac_seconds(channel,width_mhz) — cached
    // --- the Beta-Bernoulli hold model (binary: did the rung reach & HOLD Stable?) ---
    pub successes: u32,           // count of Stable verdicts  (Beta α = successes + ALPHA0)
    pub failures:  u32,           // count of non-Stable verdicts (Beta β = failures + BETA0)
    // --- the EMA models for continuous, drifting quantities ---
    pub busy_ema: f32,            // 0..100, EMA of survey busy_ratio (congestion); seed = first observed
    pub tput_ema: f32,            // EMA of a PHY-quality proxy (assoc rate / iperf / width×EIRP estimate)
    // --- bookkeeping ---
    pub obs_count: u32,           // successes + failures — drives confidence()
    pub last_seen: String,        // ISO8601 of the last observation
    pub last_outcome: String,     // last Stability variant, for the artifact
    pub decayed_at: String,       // last aging pass (D40)
}

pub struct WifiKnowledge {                 // /var/lib/hookprobe/wifi-learn-<iface>.json
    pub schema: u32,                       // = WIFI_LEARN_SCHEMA
    pub iface: String,
    pub fw_id: String,                     // kernel+driver+firmware fingerprint (D38 rehabilitation trigger)
    pub entries: Vec<ConfigStat>,          // bounded to MAX_LEARN_ENTRIES; evicted per retention_priority
    pub updated_at: String,
}
```

**Bounded + eviction.** When `entries.len() > MAX_LEARN_ENTRIES` after an insert, evict the single
lowest `retention_priority(stat, now)` where
`retention_priority = confidence(stat) * recency(stat.last_seen, now)` and `recency` decays with age
(e.g. `0.5^(age_days / STALE_HALF_LIFE_DAYS)`). This keeps **both** high-confidence *good* winners
**and** high-confidence *known-bad* entries (both are valuable, both are recent-or-confident), and
sheds only low-confidence, stale, half-explored cells — never a config we are sure about. Entries for
a regdomain the box no longer sits in age out naturally. Memory ≈ 64 × ~140 B ≈ 9 KB; CPU = one
≤64-row scan per decision. Edge-honest.

**What it subsumes (recommended: the model ABSORBS all three prior caches; they become derived exports,
not independently-maintained state):**

| Prior artifact | Was | Becomes |
|---|---|---|
| `BandLkg` (D19, built) | last-good rung label per (cc, radio) | the `argmax quality_score` entry among current-legal high-confidence stats — `wifi-band-lkg-<iface>.json` is still WRITTEN (for the existing boot-fast-path reader `start_rung`) but **rendered FROM the model**, never maintained in parallel |
| `ChannelLkg` (D31, spec) | last validated 5 GHz channel | the `argmax quality_score` 5 GHz entry — `wifi-channel-lkg-<iface>.json` likewise an export |
| `OptimizeState.blocked_channels` (D30, spec) | boolean bad-list | `is_known_bad(stat)` = a *learned probability* + confidence + a re-probe window (D38) — strictly more general |
| `OptimizeState.dfs_ap_supported` (D30, spec) | one boolean per radio | derived: `dfs_ap_supported = false` iff EVERY confident DFS entry is known-bad; otherwise per-block hold_prob resolves it |

Rationale for absorb-not-layer: three last-only caches with overlapping (radio, regdomain, channel,
width) coordinates ARE the "remembers only the last outcome" limitation the operator wants gone.
One keyed accumulating table is a superset of all three — each old artifact is a *projection*
(band-LKG = the winning entry's rung, channel-LKG = its channel, blocked = the low-hold entries).
Keeping the old JSON files as **read-only exports written from the model** means D19/D31's boot-fast-path
readers and the D24 precedence chain need **zero change** — they consume the projection; the model is
the source of truth behind it. `channel_lkg_valid`/`band_lkg_valid` stay as-is (still gate the
exports on cc/radio match).

### D36 — The update rule + quality_score + confidence (the learning curve, and why it CONVERGES)

**Single write path** — both the boot calibrate loop (every rung it applies + `verify_rung` verdict)
AND the 3 AM optimizer (every candidate it measures/validates) call ONE function:

```rust
pub struct Observation<'a> {
    pub key: ConfigKey, pub center_idx: u32,
    pub verdict: Stability,           // from verify_rung (the SAME binary hold signal both layers already produce)
    pub busy_ratio: Option<u8>,       // survey, if measured (optimizer path); None on the boot path
    pub tput_proxy: Option<f32>,      // assoc rate / iperf / None
    pub now: &'a str,                 // ISO8601
}
/// Incremental, online, O(1) update of one cell (creating it on first sight). No batch, no training.
pub fn record_observation(m: &mut WifiKnowledge, o: &Observation);
```

- **Hold (binary) — Beta-Bernoulli, the conjugate model.** `verdict.is_stable()` ⇒ `successes += 1`,
  else `failures += 1`. Priors `ALPHA0 = 1.0, BETA0 = 1.0` (uniform — an unseen config starts at
  hold_prob 0.5, "unknown," which the exploration bonus then resolves fast). The **hold-probability**
  is the posterior mean, and its **confidence** is the posterior concentration:
  ```rust
  pub fn hold_prob(s: &ConfigStat) -> f32 { (s.successes as f32 + ALPHA0) / (s.obs_count as f32 + ALPHA0 + BETA0) }
  pub fn confidence(s: &ConfigStat) -> f32 { s.obs_count as f32 / (s.obs_count as f32 + CONF_K) } // CONF_K = 2.0
  ```
  Beta-Bernoulli is textbook: the mean → the true hold rate and the variance → 0 as `obs_count → ∞`
  (law of large numbers) — a **provable convergence**, with two integers of state. `confidence` with
  `CONF_K=2` reaches 0.60 at obs=3 and 0.75 at obs=6 — a couple of confirmations, not hundreds.
- **Congestion + throughput (continuous, drifting) — EMA.** `busy_ema ← (1-η)·busy_ema + η·busy`,
  `η = EMA_ALPHA = 0.3`; first observation seeds it directly (no cold-0 bias). Same for `tput_ema`.
  EMA converges to the mean under stationary load and *tracks* drift under a changing RF environment
  (the D40 aging requirement) — exactly why continuous signals use EMA, not counts.

**quality_score — the exploitation ranking (higher = better).** Multiplicative in hold_prob so a
config that does not HOLD can never win, additive in the throughput/headroom/congestion terms:

```rust
pub struct QualityWeights {          // code-tuned defaults, NOT operator intent (like OptimizeWeights, D28)
    pub cap_vht80: f32,   // 100.0   base capacity of an 80 MHz rung
    pub cap_ht40:  f32,   //  50.0
    pub cap_ht20:  f32,   //  25.0
    pub w_busy:    f32,   //   0.6   congestion cost per 1% busy
    pub eirp_per_db: f32, //   2.0   headroom bonus per dBm above the 23 dBm UNII-1 floor (D28 parity)
    pub cac_cost:  f32,   //   8.0   flat adoption-cost penalty for a DFS rung (60 s outage to switch to it)
}
pub fn quality_score(s: &ConfigStat, eirp_dbm: u32, w: &QualityWeights) -> f32 {
    let cap = match s.key.width_mhz { 80 => w.cap_vht80, 40 => w.cap_ht40, _ => w.cap_ht20 };
    let headroom = w.eirp_per_db * (eirp_dbm.saturating_sub(23) as f32);
    let raw = cap + headroom - w.w_busy * s.busy_ema - if s.dfs { w.cac_cost } else { 0.0 };
    hold_prob(s) * raw.max(0.0)      // hold_prob gates: known-bad (hold_prob→0) ⇒ quality→0 ⇒ never argmax
}
```

Because `quality_score` multiplies by `hold_prob`, **never-repeat-known-bad is automatic**: a config
learned bad collapses to ~0 quality and is never the argmax. The learning curve IS the trajectory of
`(confidence, quality_score)` for the winning key over time — monotone-ish up as observations
accumulate, and it is exactly what D43 emits for Mission Control to plot.

### D37 — Direct-to-best (exploitation): two tiers, keyed on confidence — "doesn't repeat, gets straight there"

The boot path consults the model FIRST. Two exploitation tiers, so the "doesn't repeat the same
calibration twice" win lands after the **first** good outcome and the full "gets DIRECTLY there" skip
lands once we are sure:

```rust
pub enum BootPlan {
    /// Tier-2 EXPLOIT: high confidence — SKIP the ladder entirely; render this (channel,width),
    /// ONE clean_restart, ONE verify. O(1) boot. Fall to Ladder only if that single verify fails.
    DirectToBest { stat: ConfigStat, quality: f32, confidence: f32 },
    /// Tier-1 RESUME: some confidence — start the ladder AT this rung's index (the existing
    /// start_rung behaviour, now model-fed), no VHT80 re-thrash. This is the band-LKG win, generalised.
    ResumeAtRung { label: String },
    /// COLD / low-confidence / model-miss just occurred — run the full D6/D20 ladder from the top.
    Ladder,
}
/// legal = the ladder-derived currently-SAFE (channel,width) set (ap_capable ∩ reg_channels ∩ radio caps);
/// the model may ONLY choose among these (always-joinable — D41).
pub fn plan_boot(m: &WifiKnowledge, cc: &str, radio_id: &str, legal: &[(u32,u32)],
                 eirp_of: impl Fn(u32)->u32, w: &QualityWeights) -> BootPlan;
```

Selection = **argmax `quality_score` over `{ stat : stat.key matches (radio_id,cc) ∧ (channel,width)∈legal ∧ !is_known_bad(stat) }`**, then gate the tier:

- winner `confidence ≥ DIRECT_CONFIDENCE (0.60)` **and** `hold_prob ≥ DIRECT_HOLD (0.80)` ⇒
  `DirectToBest` (skip the ladder, single verify). With uniform priors, 3 clean holds → hold_prob 0.80,
  confidence 0.60 — so by the ~4th boot the box goes straight to the best channel+width with no probe.
- winner exists but below that gate (≥1 Stable seen) ⇒ `ResumeAtRung` — starts the ladder at the
  proven rung (no wasted VHT80 attempt on a radio already shown to need HT40). This is the
  from-observation-#2 "doesn't repeat" guarantee.
- nothing legal-and-not-known-bad, or cold model ⇒ `Ladder`.

A `DirectToBest` whose single verify comes back non-Stable (rare — environment/firmware changed since)
records the failure via `record_observation` (dropping its hold_prob/quality) and **falls to `Ladder`
from the top** the same boot — a model miss degrades to the safe ladder, never to a dead AP (D41).

### D38 — Never-repeat-known-bad: a learned probability + a re-probe window + firmware rehabilitation

Generalises `blocked_channels` (boolean) and `dfs_ap_supported` (boolean) to a learned, decaying signal:

```rust
pub const BAD_HOLD: f32 = 0.25;       // hold_prob at/below this = "bad"
pub const BAD_CONFIDENCE: f32 = 0.60; // …but only trust "bad" once we are this sure
pub const REPROBE_WINDOW_DAYS: f32 = 30.0;
pub fn is_known_bad(s: &ConfigStat, now: &str) -> bool {
    hold_prob(s) <= BAD_HOLD
        && confidence(s) >= BAD_CONFIDENCE
        && age_days(&s.last_seen, now) < REPROBE_WINDOW_DAYS   // after which it is re-probe-eligible again
}
```

A config confidently learned bad (e.g. brcmfmac `5GHz-VHT80-ch36`, which drifts to a DFS channel and
never settles) is skipped **forever** by `plan_boot`/`optimize_candidates` — *until* the re-probe
window elapses, when `is_known_bad` returns false and the explorer (D39) may try it **once** more
(rehabilitation after an environment change). Two forcing rehabilitations short-circuit the 30-day wait:

- **Firmware/driver change.** On load, if `WifiKnowledge.fw_id != current_fw_id`, apply a one-time
  strong decay to EVERY entry's `failures` (halve β, `failures = failures/2`) and stamp the new fw_id.
  A firmware update that fixes a chanspec bug thus gets a re-probe chance *without* full amnesia (the
  successes — the things that worked — are preserved). fw_id is NOT in the ConfigKey (that would
  explode the table and discard history on every kernel bump); it is a model-level rehabilitation
  trigger.
- **Regdomain change** already invalidates the *exports* (band/channel-LKG `*_valid`); the model
  keeps the foreign-regdomain entries (a box that returns to that country reuses them) but they are
  simply not `legal` in the new domain, so they cannot be selected.

`dfs_ap_supported` is now DERIVED, not stored: `dfs_ap_supported(m, cc, radio) = ` *not* (every
confident DFS entry for this (cc,radio) is known-bad). The optimizer reads this derived value to
decide whether to bother enumerating DFS candidates — one confident DFS success anywhere flips it true.

### D39 — Explore/exploit: a deterministic UCB contextual bandit (the improvement curve), budgeted to the 3 AM optimizer

The **boot path is pure exploitation** (D37) — bring-up is never the place to gamble. **Exploration is
the 3 AM optimizer's job** (D25 timer), budgeted to **at most ONE exploration per run** (matching D28's
one-switch-per-run disruption cap). The selection is a **deterministic UCB1** score (auditable — no
RNG in the decision; the timer's `RandomizedDelaySec` already de-synchronises a fleet):

```rust
pub const EXPLORE_C: f32 = 14.0;      // exploration weight (quality-units), tuned
pub const MIN_OBS: u32 = 3;           // below this, a legal config is "under-observed" → explore-eligible
pub const EXPLORE_EVERY: u32 = 7;     // cadence: explore even a mature set every Nth run (catch drift)
/// UCB objective over the legal, not-known-bad candidate set for THIS (cc,radio):
///   ucb(stat) = quality_score(stat) + EXPLORE_C * sqrt( ln(total_obs+1) / (obs_count+1) )
/// Exploit picks argmax quality_score; explore picks argmax ucb (favours high-uncertainty cells).
pub enum OptimizeMode { Exploit, Explore }
pub fn choose_mode(m: &WifiKnowledge, cc: &str, radio: &str, run_counter: u32, env_changed: bool) -> OptimizeMode;
pub fn pick_candidate(m: &WifiKnowledge, cc: &str, radio: &str, legal: &[(u32,u32)],
                      mode: OptimizeMode, w: &QualityWeights) -> Option<ConfigKey>;
```

`choose_mode` returns `Explore` when ANY of: (a) a legal, not-known-bad config has `obs_count < MIN_OBS`
(unmeasured knowledge to gain); (b) the cadence hits — every `EXPLORE_EVERY`th run explore even a
mature set (catch drift / a newly-installed neighbour AP); (c) `env_changed` — the current channel's
`busy_ema` jumped by ≥ a threshold, or a regdomain change fired the optimizer. Otherwise `Exploit`
(the common nightly result: re-measure the incumbent, `Keep` — no disruption). An explored candidate
runs the **exact D29 validate→commit/revert loop** (DFS-aware CAC via `select_settle_seconds`), and its
result is fed back through `record_observation` — that update *is* the improvement curve: each
exploration tightens one Beta posterior (confidence↑) and refreshes its EMA. UCB provably concentrates
sampling on the best arm as `total_obs` grows → the ranking converges, the exploration bonus shrinks,
and the optimizer settles into `Keep` — a self-terminating improvement curve.

### D40 — Decay / aging: discounted Beta + EMA drift (so a changed RF environment forces re-exploration, not stale trust)

Applied once per optimizer run (and on load), BEFORE selection, by a pure pass:

```rust
pub const STALE_HALF_LIFE_DAYS: f32 = 21.0;
/// Geometric discounting of the Beta counts toward the prior for stale cells: this REDUCES
/// confidence (concentration) while PRESERVING the mean, so a stale winner becomes explore-eligible
/// again (its UCB bonus rises) without being forgotten. EMA needs no explicit decay (it is already a
/// forgetting filter), but a cell not observed for a long time has its busy/tput treated as unknown
/// by widening its exploration bonus, not by trusting the old number.
pub fn age_model(m: &mut WifiKnowledge, now: &str);   // successes,failures *= 0.5^(age/HALF_LIFE) when age>0
```

Discounted Beta is the standard non-stationary-bandit fix: old evidence loses *weight* geometrically,
so a config that held six months ago but now sits behind a new interferer will, on its next
exploration, move its mean quickly (few high-weight recent observations dominate the decayed old ones).
This is precisely the "don't trust a stale win" requirement — aging + UCB *forces* periodic
re-validation of even a long-standing champion (cadence rule D39b), and a genuinely-changed
environment re-sorts the table within a couple of runs. (`successes`/`failures` become `f32` internally
for the discount; the round-trip JSON stores them as floats — a 3-success cell aged once is `1.5`, still
`hold_prob ≈ 0.71`, `confidence` lowered — exactly the intended "still believe it, but re-check.")

### D41 — Convergence, anti-flap, and the always-joinable invariant (non-negotiable)

- **O(1) warm boot.** With the model warm, `plan_boot` returns `DirectToBest` → render → one
  clean_restart → one `verify_rung`. That is `O(1)` (a single settle), not `O(ladder)`. Proven by
  construction: the ladder is only reached on a cold model or a verify miss.
- **Anti-flap (hysteresis on quality).** The optimizer switches the incumbent only when
  `quality(candidate) ≥ quality(current) + QUALITY_SWITCH_MARGIN (8.0)` **and** the candidate's
  `confidence ≥ current.confidence` (never flap toward an under-observed cell). Two near-equal configs
  therefore cannot oscillate — the incumbent wins ties. This composes with (does not replace) D28's
  `switch_margin`/`quiet_floor_busy` gates; both must pass.
- **Always-joinable — the model NEVER overrides safety.** `plan_boot`/`pick_candidate` choose ONLY
  among the caller-supplied `legal` set (`ap_capable_5ghz` ∩ `reg_channels` ∩ `RadioCaps` ∩ the D6
  ladder rungs). The ch40 anchor and the 2.4/HT20 floor are ALWAYS in that set and are ALWAYS
  ladder-terminal (D20). The model can only *reorder or skip-to-within* validated-safe options; it
  can neither invent an unsafe config nor suppress the floor. Every model miss, every known-bad
  cascade, every empty-legal-set case degrades to the D6/D20 ladder → the terminal floor. The model
  makes the box *smarter*, never *un-joinable*.

### D42 — Integration + precedence (one store feeds boot, the optimizer, and the exports; the pin always wins)

Extends the D24 precedence chain; the model slots at prio-2, **superseding** band-LKG + channel-LKG:

| Prio | Source | Authority |
|---|---|---|
| 1 | **Operator hard-pin** (`wifi.ap.channel` / `band: "5"\|"2.4"`) | ALWAYS wins. The model **records** observations for the pinned config (learning never stops) but has **no selection authority** while a pin is set. A pinned DFS channel is still CAC-validated and still reverts to ch40 if it cannot hold (D24 — always-joinable outranks even a pin). |
| 2 | **The learning model** (`plan_boot` DirectToBest / ResumeAtRung; `pick_candidate` for the optimizer) | Supersedes + writes the band-LKG and channel-LKG exports. |
| 3 | **Boot ladder** (D6/D20) | Cold-model / low-confidence / model-miss backstop. |
| 4 | **2.4/HT20 floor** | Terminal, always-joinable. |

- **Boot calibrate** (`network-apply.sh` → the `--wifi-calibrate` path): call `plan_boot`; act on the
  tier; call `record_observation` for every rung verdict; on settle, rewrite the band/channel-LKG
  exports from the model's current argmax.
- **3 AM optimizer** (`wifi-optimize.sh`/`--wifi-optimize`): `age_model` → `choose_mode` →
  `pick_candidate` → the existing D29 validate→commit/revert → `record_observation` → rewrite exports +
  `OptimizeOutcome`/artifact. `reapply` (D31 post-boot DFS restore) becomes "validate the model's
  argmax DFS entry," identical machinery.
- **Model lifecycle:** created empty on first boot; `fw_id`-rehabilitated on firmware change (D38);
  entries evicted per D35; never blocks boot (read is a file load with a cold-model fallback).

### D43 — Observability: the store IS an artifact + a per-decision explanation with the learning curve

The store file `/var/lib/hookprobe/wifi-learn-<iface>.json` is itself an evidence-graph artifact
(every cell shows successes/failures/hold_prob/confidence/busy_ema/quality — the operator can read the
whole knowledge base). Each boot/optimizer decision additionally emits a `LearnDecision` (appended to
`wifi-calibration.json` / `wifi-channel-optimize.json`, D9/D32):

```rust
pub struct SkippedConfig { pub label: String, pub reason: String }   // "known_bad(hold=0.05,conf=0.9)" | "illegal_regdomain" | "lower_quality(72<91)" | "under_confidence"
pub struct CurvePoint    { pub at: String, pub quality: f32, pub confidence: f32, pub hold_prob: f32 }
pub struct LearnDecision {
    pub iface: String,
    pub mode: String,                    // "direct_to_best" | "resume_at_rung" | "ladder_fallback" | "explore" | "exploit_keep" | "exploit_switch"
    pub chosen: Option<String>,          // the winning ConfigKey label
    pub chosen_quality: f32, pub chosen_confidence: f32, pub chosen_hold_prob: f32,
    pub skipped: Vec<SkippedConfig>,     // WHY each alternative was not taken (known-bad, illegal, lower-quality, under-confidence)
    pub curve: Vec<CurvePoint>,          // the winning key's (quality,confidence,hold_prob) trajectory — the visible improvement curve
    pub decided_at: String,
}
impl LearnDecision { pub fn to_json(&self) -> String; }
```

This is the "AI explanation panel / why · confidence · evidence" surface for the Wi-Fi radio in
Mission Control (Observe / Administration): the operator SEES that the box jumped straight to
`5GHz-VHT80-ch40` (hold 0.98, conf 0.95, quality 92), skipped `5GHz-VHT80-ch36` as known-bad
(hold 0.05), and is periodically exploring `5GHz-VHT80-ch100` (DFS, obs 2, high uncertainty) — and
can plot `curve` to watch the learning curve rise and flatten. telemetry-analyst gets per-platform
truth of which configs each radio really holds, accumulated rather than last-only.

### D44 — Tests + gates + migration

- **T1 pure (`wifi_calibrate.rs`):** `record_observation` (Beta counts increment on the right verdict;
  EMA seed-then-blend; cell creation on first sight); `hold_prob`/`confidence` (uniform-prior means;
  confidence 0.60@obs3, 0.75@obs6; 3 holds → hold_prob 0.80); `quality_score` (hold_prob gates known-bad
  to ~0; VHT80 > HT40 > HT20; +EIRP lifts a clean DFS block; busy penalty); `plan_boot` (DirectToBest
  only when conf≥0.60 ∧ hold≥0.80 ∧ legal ∧ not-known-bad; ResumeAtRung after 1 Stable; Ladder when
  cold; a DirectToBest verify-miss → Ladder same boot); `is_known_bad` (learned-bad threshold; re-probe
  window reopens it; fw_id change halves failures); `age_model` (discounted counts preserve mean, drop
  confidence); `choose_mode`/`pick_candidate` (Explore on under-observed / cadence / env-change; UCB
  favours high-uncertainty; Exploit argmax quality; one-per-run); anti-flap (`QUALITY_SWITCH_MARGIN`
  holds the incumbent on a tie); eviction (lowest confidence×recency evicted at MAX_LEARN_ENTRIES,
  never a confident cell); `LearnDecision::to_json`/`WifiKnowledge` round-trip; **convergence property
  test:** feed N synthetic Stable observations for A and mostly-fail for B → quality(A) strictly rises
  and its confidence → the saturation, quality(B) → ~0, and `plan_boot` flips from Ladder → ResumeAtRung
  → DirectToBest(A) at the specified obs counts (the machine-checked "learning curve").
- **T2 shell (shellcheck + bats):** the calibrate/optimize scripts persist + reload the store, write
  the band/channel-LKG exports FROM it, and never block boot on a missing/corrupt store (cold-model
  fallback to the ladder).
- **T3 QEMU arm64:** store survives a reboot; a warm store makes the second boot take the DirectToBest
  path (asserted via the `LearnDecision.mode` artifact); the optimizer timer stays off the boot
  critical path.
- **Metal gate (acceptance, CM5/Pi5):** across several reboots the model converges to
  `5GHz-VHT80-ch40`, marks `5GHz-VHT80-ch36` known-bad after ≤2 failures and never re-probes it inside
  the window, boots O(1) once warm, and — on a forced regdomain change — re-fights from the ladder
  while retaining the foreign-domain knowledge. Honest limit: real per-site drift and a real firmware
  fix rehabilitating a known-bad config cannot be reproduced off-metal.
- **Migration:** no schema break — `BandLkg`/`ChannelLkg`/`OptimizeState` structs remain (as export
  targets); a box with an existing band-LKG seeds the model with one Stable observation for that rung
  on first run (so it starts at ResumeAtRung, not cold). `MAX_LEARN_ENTRIES`, the weights, and the
  thresholds are code-tuned defaults (like `OptimizeWeights`), NOT operator intent — one field round
  of calibration before the model is trusted for DirectToBest in a release (until then it may run in
  ResumeAtRung-only "shadow" mode, recording without skipping the ladder).

## Consequences

- **Compliance is enforced by the kernel regdb, chosen by our detection, overridable by intent** —
  a coherent chain with the operator always able to win.
- **brcmfmac is now first-class at VHT80**, not HT20-capped — the correction materially raises the
  edge AP's real throughput (78 → 351 Mbit/s measured) with no new hardware.
- **A durable default-supplicant bug is fixed by construction** (role-driven `supplicant_policy`),
  benefiting every AP-role radio, not just brcmfmac.
- **Adding a radio stays one manifest fact** — `RadioCaps` from `iw phy` drives the ladder; no new
  branch per chip.
- **Consistency with "operated by intent / config is a generated artifact"
  (`docs/architecture/Readme.md:150,181`, CLAUDE.md decision #3) — flagged, product-steward.** D11 phase (b)
  fires `hookprobe-regdomain-reresolve.service` on `network-online` and, if a better/valid CC
  resolves, autonomously STOPs hostapd + `iw reg set` + re-runs the reconcile **without** an
  operator-approved plan-as-a-diff. This is CONSISTENT with the model: the regdomain is an
  **environment-derived compliance FACT** (like a DHCP lease, a WAN exit IP, or a first-boot manifest
  re-probe), not an operator preference — exactly the class the **deterministic reconciler**
  converges autonomously (`Readme.md:165,173`), and operator **intent** (`wifi.country:`) still
  ALWAYS wins (D3 prio a). The out-of-band trigger is a reconcile INPUT, not a second config
  interface. **Worth one explicit clause in Readme Pillar 3** (proposed, Amber — not silently
  edited): environment-derived compliance facts are converged by the deterministic reconciler
  without a diff/approval, and only operator-*intent* changes go through the plan-as-a-diff loop.

## Residual risks / honest limits

- The runtime service's per-rung rendering is currently an inline mirror of the Rust ladder for the
  two universally-safe blocks; the authoritative path (a `hookprobe-supervisor --wifi-calibrate`
  subcommand emitting the ladder + confs + `CalibrationOutcome`) is **not built yet**. Until then
  the two could drift — mitigated by keeping the inline set minimal and cross-referenced, and by the
  Rust core being the single source of the compliance-critical logic.
- The calibration loop is **not yet metal-validated as a service** (the individual facts — VHT80
  holds after supplicant mask, RO detected from WAN — ARE metal-proven; the automated loop that
  ties them together is not). Needs a verification-engineer gate on a CM5/Pi5.
- The MCC/timezone tables are representative, not exhaustive; an unlisted input degrades to the
  world domain (safe, if suboptimal). Extending them is data-only.
- The embedded GeoIP DB is a **pinned snapshot** — country reassignments drift over time; a stale DB
  only degrades the *hint* (operator intent + on-device `wireless-regdb` still govern compliance), and
  an air-gapped box never needs a refresh. `base/data/ip-location-db/refresh.sh` re-pins it (data-only).
- The GeoIP rung's worst case (a near-max exit IP, no earlier rung resolving) is a full `zcat`+scan
  of the ~8.6 MB IPv4 CSV — ~0.3 s typical (early-exit), ~2 s worst on the dev box (a few seconds on a
  Pi). It runs **only** on a cold, no-intent, no-LKG, no-modem first boot; a configured or
  previously-resolved box never reaches it. Acceptable for a boot oneshot; not on the packet path.
- `reg_channels` is a coarse guardrail, not a full regdb; correctness ultimately rests on the
  on-device `wireless-regdb`. If a device ships without a current regdb, `iw reg set` is a no-op and
  the domain stays at the kernel default — the loop still won't propose DFS, but power limits may be
  conservative. Baking a current `wireless-regdb` into the image is assumed (existing packaging).
- **(D24–D33 optimizer)** DFS in AP mode on brcmfmac FullMAC is UNCONFIRMED; the design does not assume
  it — it tests once and learns `dfs_ap_supported` (D30), so the worst case is "the optimizer proves the
  radio can't DFS, disrupts the AP once for ~60 s, then Keeps ch40 forever." On a radio that CAN DFS, the
  one-time adoption of a cleaner block costs a single 60 s CAC outage (or 600 s if meteo is opted in). A
  real `DFS-RADAR-DETECTED` mid-operation forces an immediate regulatory vacate to ch40 — a legitimate,
  compliance-mandated client disruption the optimizer cannot avoid (and correctly prioritises over
  throughput). Off-channel survey briefly takes the AP off its channel (≤2 s budget) — clients see a
  short stall, never a disconnect; a radio that refuses off-channel survey degrades to scan-only
  `bss_count` scoring. The whole optimizer is opt-outable (`optimize.enabled: false`) and DFS-outable
  (`allow_dfs: false`), in which case the box behaves exactly as today (ch40 anchor, no scheduled
  disruption). The scoring weights (D28) are code-tuned defaults, not operated — they will need one round
  of field calibration against real 03:00 surveys before the optimizer is enabled-by-default in a release.

## Extension 2026-07-17 (RC-DFS) — WHY DFS does not work in AP mode on the onboard brcmfmac (DEFINITIVE root cause, firmware/CLM forensics)

The D30 "test once and learn `dfs_ap_supported`" seam was designed BEFORE we knew whether DFS-AP
was a config bug on our side or a hardware/firmware limitation. The exhaustive EU channel matrix
(run on real Pi4 **and** CM5 metal, 2026-07-17, radio-reset between every channel to kill stale
readings) resolved it empirically, and this section root-causes it against upstream firmware so the
`allow_dfs: false` default is understood, not merely observed.

**Empirical result (both boards, reset-clean):** ONLY UNII-1 (ch 36/40/44/48) brings up an AP at
HT20/HT40/VHT80. **Every** DFS channel (52–140) FAILS identically — hostapd stays `activating`, the
radio drifts to ch34/20 MHz, and `iw reg get` reports `phy#0 country 00: DFS-UNSET` **despite**
`iw reg set RO` having succeeded at the kernel layer. The AP simply never beacons on a DFS channel.

**Are we doing something wrong? No — not fixably within the supported firmware channel.** This is a
compounding *two-layer* firmware/regulatory limitation, and neither layer is a config error on our
side. Forensics (versions pulled from `RPi-Distro/firmware-nonfree` @ `1:20260519`, the **current**
May-2026 package, and from the running boards):

- **Layer 1 — the stock Cypress CLM regulatory blob does not enable DFS for AP operation.** The
  shipped `cyfmac43455-sdio.clm_blob` is `CLM DATA 1.29.4 / ClmImport 1.39.1`, and it is **byte-
  identical** (`sha256 9823842cae9fb9a5dd1e5fb31f595516ec7deee341354bef30bb3026eee29cc1`) to what the
  newest upstream firmware-nonfree ships — i.e. it is NOT stale; it is *current*, and DFS-AP is still
  off. Enabling DFS channels needs a **custom/region-specific CLM blob** (the community NL/ETSI hacks)
  — an unsigned, non-Debian regulatory blob. Under trust-nothing-unsigned (ADR 0002) that is a
  supply-chain regression we will not take for a marginal capability. (Cf. `raspberrypi/linux#3659`:
  a *missing* clm_blob already yields "limited channels available"; the *stock* blob is DFS-limited by
  design.)
- **Layer 2 — the firmware refuses the regulatory-domain handoff ("country 99: DFS-UNSET").**
  brcmfmac `7.45.234` (our current build) and even `7.45.265` (the **newest** in RPi-Distro, built
  `2023-08-29`) carry the known `brcmf_cfg80211_reg_notifier: Firmware rejected country setting` bug
  (`raspberrypi/linux#6669`): the kernel regdomain is set, but the FullMAC firmware stays at world
  domain, treats every DFS channel as radar-unknown, and (correctly, as a safety default) will
  not initiate radiation on it. **This is caught in the act, live, on the running Pi4 (2026-07-17)** —
  `iw reg get` shows the split unambiguously:
  ```
  global
  country RO: DFS-ETSI          # ← the KERNEL accepted RO; DFS sub-bands 5250-5350 / 5470-5725 known
  phy#56
  country 99: DFS-UNSET         # ← the FIRMWARE is stuck at world domain, DFS UNSET — handoff FAILED
  ```
  With the firmware self-managed domain at `99/DFS-UNSET`, the AP can only bring up a non-DFS channel:
  the same board's calibration settled on `channel 40 (5200 MHz), width 80 MHz, center 5210` — UNII-1
  VHT80, precisely the matrix's "only UNII-1 holds" result. The kernel regdb is NOT the blocker (it has
  RO/DFS-ETSI); the driver→firmware country handoff is. **The upstream fix (Infineon `7.45.286`, Oct-2024) exists ONLY in
  Infineon's out-of-tree `ifx-linux-firmware` repo — it is NOT in the RPi/Debian `firmware-nonfree`
  channel** that we, and every stock Raspberry Pi OS, build from. Bumping firmware *within* the
  supported channel (7.45.234 → 7.45.265) does NOT fix it: 7.45.265 is itself the version #6669 flags
  as broken.
- **The silicon is not the blocker.** The firmware image advertises `dfsradar` in its feature string
  and links `wlc_dfs_attach` / `wlc_cac_attach` / `dfsr`/`dfar` — the BCM43455 *can* do DFS/CAC. What
  is missing is (a) DFS enablement in the regulatory blob and (b) a firmware that accepts the country
  handoff. Both are regulatory-data / firmware-version gates, not absent hardware capability.
- **Even if both were fixed, FullMAC AP-mode DFS is fragile.** Infineon's own developer community
  documents "CYW43455 STA mode fails for DFS-enabled channels in concurrent STA and AP mode" — the
  FullMAC firmware performs DFS/CAC *internally* for STA, and AP-mode radar handling is exactly where
  it breaks. For an appliance whose invariant is *the AP is always joinable*, an unreliable DFS-AP is
  worse than none.

**The fix was TESTED on metal (2026-07-17) — it does NOT work.** To answer "can we update the
firmware/driver to make it work?" empirically rather than by inference, we ran the strongest available
lever on the live Pi4: swapped the running firmware for **Infineon `7.45.286` (dated 2024-10-28 — the
exact #6669 fix)** plus Infineon's **fuller 4733-byte CLM** (vs the RPi/Debian 2676-byte `clm_min`
blob), reloaded `brcmfmac`, and re-applied the country. Result:
- The new firmware loaded (`dmesg`: `version 7.45.286 (be70ab3 CY)`), but the firmware regdomain
  **stayed `country 99: DFS-UNSET`** — the country handoff still fails, *with the fixed firmware*.
- Every DFS channel (52–144) still enumerated **`(disabled)`** in `iw phy channels`; only the non-DFS
  UNII-1 channels stayed enabled.
- The decisive test — `hostapd` on DFS ch100 — failed immediately: `IEEE 802.11 Hardware does not
  support configured channel` → `Could not select hw_mode and channel (-3)` → `AP-DISABLED`. Not a
  CAC-wait; the DFS channel is simply not in the hardware's available list.
A second lever was then tested — **NVRAM `ccode=RO`/`regrev=0`** written into the per-model NVRAM
`.txt` (a config file we *do* vendor and sign, so it would be shippable if it worked). It also failed:
firmware still `country 99: DFS-UNSET`, DFS channels still unavailable, and hostapd on ch100 now gave
the most explicit diagnosis of all — `Frequency 5500 (primary) not allowed for AP mode, flags:
0x30197b NO-IR RADAR`. The DFS channels are flagged **NO-IR** (no-initiating-radiation, i.e. an AP may
not beacon) precisely because the firmware, locked to world domain, refuses to provide the radar
detection that would clear them.

So neither a newer *driver/kernel* (we already ship a current edge kernel), NOR a newer *firmware*
(7.45.286, the #6669 fix), NOR a *fuller CLM* (Infineon's 4733-byte blob), NOR an *NVRAM `ccode`
config* moves the firmware off world domain or opens DFS-AP. Every lever short of binary-patching the
firmware (nexmon-style RE — unsigned, unmaintainable, and against ADR 0002) has been tested on real
silicon and failed. The original firmware + NVRAM were restored on the board afterward. This converts
the conclusion below from "unsupported, don't chase it" to "**tested end-to-end across every
config/firmware/CLM/NVRAM lever, and none of the available fixes work.**"

**Decision (confirms, now root-caused AND fix-tested, `allow_dfs: false` as the shipped default):**
1. `allow_dfs` stays **false** by default on any brcmfmac FullMAC radio — already the shipped default
   (`network.example.yaml`, `wifi_calibrate.rs` `allow_dfs` default `false`), so the optimizer never
   even proposes a DFS block on this radio and there is no wasted ~60 s AP disruption. **Spec amendment
   for the D35–D44 learning model (still roadmap, not built):** when implemented, it MUST seed
   `dfs_ap_supported = false` for the `(brcmfmac, *)` radio class so the DFS probe is *skipped by
   construction*, not attempted-then-reverted; only a SoftMAC/mac80211 radio (a USB adapter) may
   attempt DFS-AP. This is the durable "never retry known-bad" outcome the learning model exists to
   encode — with today's `allow_dfs: false` default, the safe behaviour already holds without it.
2. We do **not** vendor Infineon's out-of-channel `7.45.286` firmware or its fuller CLM — not only for
   the supply-chain reason (unsigned, out-of-tree, against ADR 0002) but because **it was tested and
   does not even work** (see the metal test above: firmware still `country 99: DFS-UNSET`, DFS channels
   still disabled, hostapd still refuses ch100). There is currently no firmware/driver/CLM combination —
   in-channel or out — that unlocks DFS-AP on this radio. If a *future* firmware is shown to fix the
   country handoff AND enable DFS-AP, this decision is revisited with a fresh metal matrix; until then
   DFS-AP on the onboard radio is a proven firmware limitation, not a gap in our code.
3. Keeping firmware **current within the channel** (7.45.234 → 7.45.265) remains worthwhile *as
   ordinary maintenance* (regdomain/TX-power correctness for non-DFS bands) — but it is explicitly
   **not** a DFS fix and must never be described as one.

**Strategic consequence → ADR 0042.** This dead-end reframed the goal: chasing DFS was chasing *parity
with a home router* (every consumer AP has DFS — it differentiates us from nothing). The radio's value
to a SOC appliance is as a **sensor**, not extra channels. `docs/adr/0042-wifi-security-surface-wids-
and-radio-tiers.md` records that pivot — Wi-Fi as a monitored security surface (WIDS: rogue-AP,
evil-twin, deauth-flood, karma), radio ability as manifest **capabilities** (`wifi_monitor`/`wifi_dfs`
hard-denied for brcmfmac by this ADR's finding), and "**own the radio, not the blob**" (a mainline
SoftMAC radio grants natively what no amount of firmware patching buys). D30's "test DFS once and
learn" is superseded for the brcmfmac radio class: the answer is known, so the probe is skipped.

**Sources:** [raspberrypi/linux#6669 — "Firmware rejected country setting"](https://github.com/raspberrypi/linux/issues/6669) · [RPi forum t=392203 — brcmfmac stuck DFS-UNSET](https://forums.raspberrypi.com/viewtopic.php?t=392203) · [raspberrypi/linux#3659 — no clm_blob → limited channels](https://github.com/raspberrypi/linux/issues/3659) · [Infineon community — CYW43455 STA fails DFS in concurrent STA+AP](https://community.infineon.com/t5/AIROC-Wi-Fi-and-Wi-Fi-Bluetooth/CYW43455-STA-mode-fails-for-DFS-enabled-channels-in-concurrent-STA-and-AP-mode/td-p/340650).

## Extension 2026-07-17 (BUG-W7) — the 150-Mbps bug: 80 MHz convergence is BLOCK-wise, not exact-channel

**Symptom (operator-reported, reproduced on both boards):** the AP settled on `5GHz-HT40-ch36`
(~150 Mbit/s) instead of the `5GHz-VHT80-ch40` top rung (~450 Mbit/s PHY / ~250 Mbit/s real), on every
boot, cold and warm. The journal showed the top rung "failing" identically every time:

```
rung 5GHz-VHT80-ch40 chanspec_fail_storm (ch=36 width=80MHz fails=7) — retry budget exhausted, stepping down
warm-upgrade: exhausted 3 attempts (chanspec_fail_storm, ch=36 width=80MHz fails=7) — reverting
```

**This ADR's earlier diagnosis was WRONG and is retracted.** The prior reading — "the brcmfmac needs a
thermally warm radio; one cold ~30 s attempt is too short" — produced the D45/D46 machinery
(`WARM_MIN_UPTIME_SECONDS`, a bounded warm retry loop, a warm/cold context axis in the learning
model). Warmth was never the cause, and none of that machinery could ever have fixed it.

**Actual root cause (live ground truth, CM5 + Pi4, 2026-07-17):** applying the proven VHT80-ch40 block
by hand brings the radio up **working** —

```
channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz   # hostapd active, 1 station associated
```

— i.e. the AP **is at 80 MHz, on the correct 36-48 block (center 5210)**. The brcmfmac FullMAC
firmware simply **names an 80 MHz chanspec's primary as the block's LOWEST channel (36), not the
configured control (40)**, and the 7 `set chanspec … fail` lines are one-time bring-up churn that
stops once it settles (the count stays frozen at 7; the AP serves clients happily).

`observe_rung`/[`verify_rung`] tested convergence with an **exact** `oper_ch == want_ch`, read
`36 != 40` as "not converged", and the (harmless) `fails=7` then tripped `ChanspecFailStorm` — so the
loop **reverted a perfectly healthy 80 MHz link down to HT40**. The operator's own measurement closed
the loop: once a manual probe left the radio on VHT80 with nothing to revert it, throughput went
**150 → 250 Mbit/s**.

**Decision (D47):** an 80 MHz channel is identified by its **BLOCK**, not by which of the block's four
20 MHz channels the firmware names as primary. Convergence at `width == 80` therefore accepts any
operating channel in the **same 80 MHz block** as the request (`block_center_for_channel`:
36-48→42, 52-64→58, 100-112→106, 116-128→122, 132-144→138, 149-161→155). A channel in **no** known
block (the classic ch140 drift) still fails, so the collapse detector is not blinded. **20/40 MHz keep
the exact-channel contract** — the firmware reports those faithfully, and block-leniency must not leak
into them. Implemented in both engines, byte-mirrored: `wifi_calibrate::verify_rung` +
`wifi-calibrate.sh`'s `observe_rung` (the optimizer inherits it — `wifi-optimize.sh` sources the
calibrate script and calls the same `observe_rung`).

**D48 (found in the same pass):** `wifi-optimize.sh`'s `render_candidate_conf` hardcoded
`control -eq 40` for `[HT40-]` and emitted `[HT40+]` for every other control — wrong for 56/104/120/136,
which `block_control_for` returns precisely *because* they are 2nd-of-block ([HT40-]) channels,
contradicting its own documented contract. Now derived: `center == control + 2` (2nd-of-block) →
`[HT40-]`, else `[HT40+]`. Unreachable while `allow_dfs: false` (RC-DFS) since those are all DFS —
a latent bug that would have fired the moment a SoftMAC radio (ADR 0042) enabled them.

**Lesson (the recurring failure mode):** this is the third time in this ADR that a *plausible*
radio-behaviour theory (FullMAC can't do VHT80 → actually the supplicant; DFS "validated" → actually a
stale reading; VHT80 needs warmth → actually a channel-naming quirk) survived because it was never
checked against what the radio *actually reports when it works*. The durable guard is the tests below,
which encode the real `iw dev` string, not the theory.

**Tests (T1, all green):** Rust — `vht80_ch40_reported_as_block_primary_ch36_is_converged` (the exact
metal signature: ch36/80MHz/fails=7 → **Stable**), `vht80_block_convergence_accepts_any_channel_of_the_
same_block`, `vht80_block_convergence_still_rejects_a_different_block` (ch140 → still a failure),
`narrow_widths_still_require_an_exact_channel_match`, `block_center_map_is_correct_and_refuses_unknown_
channels`. Shell — the same four cases against `observe_rung` via the `TEST_IW_INFO` feed, asserting the
live `'36 80 7'` triple returns rc=0. Workspace: **1497 tests pass, clippy 0 errors**.

**Metal gate (pending):** an unattended cold boot on both boards must land and HOLD `5GHz-VHT80-ch40`
(reported as ch36/80 MHz/center 5210) with `chosen: 5GHz-VHT80-ch40` persisted to the band-LKG — the
proof that the box now keeps the 80 MHz link it was previously discarding.

## Extension 2026-07-17 (BUG-N1) — `RequiredForOnline=` was in the wrong systemd section, so D11/W1 never actually worked

Found while metal-validating BUG-W7 on the CM5: `systemctl is-system-running` reported **`degraded`**,
with `systemd-networkd-wait-online.service` **failed** (`Timeout occurred while waiting for network
connectivity`) and `network-online.target` **inactive** — on every boot.

**Root cause:** `RequiredForOnline=` is a **`[Link]`**-section key (systemd.network(5)). Both renderers
emitted it inside `[Network]`, and networkd said so plainly, twice, every boot:

```
/etc/systemd/network/50-hookprobe-lan-wlan0.network:13: Unknown key 'RequiredForOnline' in section [Network], ignoring.
/etc/systemd/network/50-hookprobe-wan-end0.network:10:  Unknown key 'RequiredForOnline' in section [Network], ignoring.
```

So D11/W1's entire intent was **silently dropped**. The AP radio stayed "required for online";
`wait-online` blocked on `wlan0: configuring` (an AP never reaches routable, and its
`DHCPPrefixDelegation` uplink may never delegate), timed out, failed — and every unit ordered
`After=network-online.target` never fired. That includes **`hookprobe-regdomain-reresolve.service`**,
the WAN-based regdomain re-resolve. The irony: `lan.rs`'s own comment predicted this failure
*verbatim* — the author understood the problem exactly and just used the wrong section.

> **Correction (metal-verified 2026-07-17, v5 flash):** an earlier draft here speculated BUG-N1 was
> "a very likely contributor to the `cc=00`" symptom. **That was wrong and is retracted.** Post-fix,
> `network-online.target` is active and `hookprobe-regdomain-reresolve` *does* run — and still resolves
> `-> 00 (source: world)`, because on the test bench there is genuinely no country signal (no cellular
> MCC, WAN on an isolated lab net with no geolocatable public IP, UTC timezone). `cc=00` here is the
> honest world-domain answer this ADR's honest-limits already stated — NOT a BUG-N1 knock-on. (The v5
> validation *did* surface a real, previously-hidden defect in the EARLY regdomain path — **BUG-N2**,
> below.)

**Why it shipped and why the gates missed it:** the unit tests asserted only
`content.contains("RequiredForOnline=no")` — **true from any section** — so they passed against broken
output. The T3/QEMU gate "asserted `network-online.target` REACHED" and passed because in QEMU every
link configures promptly, so `wait-online` succeeds *regardless* of the ignored key. Both gates tested
a proxy, not the property.

**Fix + durable guard:** emit a real `[Link]` section (`lan.rs`: `[Match]…\n\n[Link]\nRequiredForOnline=no\n\n[Network]…`;
`multi_wan.rs`: new `LINK_SECTION_ROUTABLE`, the old `REQUIRED_FOR_ONLINE_ROUTABLE` const deleted).
Tests now assert the **section**: `multi_wan::tests::required_for_online_is_in_the_link_section_not_network`
walks `[Section]` headers the way systemd's parser does and asserts `Some("Link")`; `lan.rs` asserts the
literal `[Link]\nRequiredForOnline=no\n`. Gates: 1498 workspace tests, clippy 0 errors.

**Lesson (generalizes beyond Wi-Fi):** a `.contains()` assertion on generated config proves the *bytes*
exist — never that the *consumer honors them*. For INI/systemd output, assert the section. And the
cheapest possible audit is the daemon's own parse log: `journalctl -u systemd-networkd | grep -i
'unknown key'` would have caught this on day one, and is worth running against **every** generated unit
we ship.

**Metal gate (pending v5 flash):** `systemctl is-system-running` = `running` (not `degraded`),
`systemd-networkd-wait-online` not failed, `network-online.target` **active**, and re-check whether the
regdomain now resolves off `00`.

## Extension 2026-07-17 (BUG-N2 + v5 metal validation) — early regdomain can't persist its verdict

**v5 flash validation (both boards, unattended cold boot, 2026-07-17):**
- **BUG-W7 ✅ metal-PROVEN on the shipped image** — both Pi4 + CM5 land and HOLD
  `channel 36 / width 80 MHz / center 5210`, `chosen: 5GHz-VHT80-ch40`, converging on the **main
  ladder** (`rung 5GHz-VHT80-ch40 STABLE (…fails=7 during settle — convergence wins) — keeping`),
  no revert, no warm-upgrade needed. Operator-measured throughput 250 Mbit/s. SELFTEST PASS both.
- **BUG-N1 ✅ metal-PROVEN** — `systemctl is-system-running` = **`running`** (was `degraded`),
  `network-online.target` **active**, `systemd-networkd-wait-online` active (was failed), **0** ignored
  networkd keys (was 2), on both boards. Hybrid-signed module chain (aegis-guard/dnsxai AOT-verified)
  + eBPF TC filters on end0/wlan0 confirmed loaded — no regression from either fix.

**BUG-N2 (real defect, surfaced by the BUG-N1 fix; NOT yet fixed):** the EARLY oneshot
`hookprobe-regdomain.service` (which must set the regdomain *before* hostapd) logs
`regdomain-apply.sh:393: /run/hookprobe/wifi-country: Permission denied` → `could not write … (reconciler
falls to 00)`, on both boards, every boot. Root cause: `/usr/lib/tmpfiles.d/hookprobe.conf` creates
`/run/hookprobe` as **`hookprobe:hookprobe` mode 0755** (no write for "other"); the regdomain units run
as root but under `ProtectSystem=strict`, which typically drops `CAP_DAC_OVERRIDE`, so they cannot write
a file into a `hookprobe`-owned directory. (The later `reresolve` run *did* write it successfully on the
same box with identical unit hardening — that asymmetry is not yet explained and must be confirmed
before a fix, rather than guessed.) **Impact:** the early, pre-hostapd regdomain detection's verdict is
discarded — the reconciler always sees `00` at first hostapd bring-up, and the country is only actually
persisted later by the WAN-online `reresolve`. **MASKED on the bench** (cc=00 is the correct answer for
this no-signal lab net anyway), but on a box WITH an early country signal (e.g. a cellular MCC available
at boot) this is a real regression window: the AP would beacon under world-domain `00` until
`reresolve` fires post-`network-online` — a brief but genuine compliance concern.

**FIXED 2026-07-17 (asymmetry now explained).** The live units show `CapabilityBoundingSet=cap_net_admin`
+ `AmbientCapabilities=cap_net_admin` + `NoNewPrivileges=yes` — so `CAP_DAC_OVERRIDE` is dropped. The
early service ran while `/run/hookprobe` was still `hookprobe:hookprobe` (tmpfiles) → root-minus-
DAC_OVERRIDE cannot write into a non-owned dir → EACCES; ~7 s later another root service with
`RuntimeDirectory=hookprobe` had re-chowned the dir to `root:root`, so `reresolve` (same caps) wrote it
as *owner*. Fix: `+CAP_DAC_OVERRIDE` in both units' `AmbientCapabilities` + `CapabilityBoundingSet`
(`base/units/hookprobe-regdomain{,-reresolve}.service`) — minimal blast radius (2 root boot-oneshots),
and unlike changing the shared dir to `root:root` it leaves the `hookprobe`-user Wasm consumers
untouched. **Proven in the exact systemd context** via `systemd-run` (root + `NoNewPrivileges` +
bounding=`NET_ADMIN` → write DENIED; `+CAP_DAC_OVERRIDE` → write SUCCEEDS). Metal re-validation pending
the next flash (assert the early `hookprobe-regdomain.service` no longer logs
`wifi-country: Permission denied`).

## Proven vs pending (brutally honest)

| Item | Status |
|---|---|
| VHT80 holds on brcmfmac after masking the AP-radio supplicant | ✅ Proven live (CM5, 351 Mbit/s) |
| Regdomain detected from WAN exit (RO) | ✅ Proven live (CM5; + modem-MCC path returned RO on the dev box during this wiring) |
| `vht80_params`/`width_lines` emit the brcmfmac-safe VHT80 block (no forbidden flags) | ✅ Verified vs the working conf |
| Pure core: detection ladder, regdomain map, supplicant policy, candidate ladder, verify, cache, artifact, `resolved_country_for_render` | ✅ Implemented + 31 unit tests |
| `wifi_cfg` forced-width refactor byte-identical + `country_code` never `auto` | ✅ 19 wifi_cfg tests green |
| **Feature 1 boot wiring: regdomain oneshot (iw reg set + run-file) ORDERED before hostapd** | ✅ Implemented (`hookprobe-regdomain.service`, `regdomain-apply.sh`); not yet metal-run as a unit |
| **Supervisor resolves `auto`→detected-CC; `network.example.yaml` no longer hardcodes GB** | ✅ Implemented + tested |
| **GAP-R1: `regdomain-apply.sh` always exits 0 + always writes a valid token (never empty)** | ✅ Implemented + verified (exit 0 even with `iw`+run-file write both failing) |
| **Offline GeoIP rung: embedded ODC-PDDL `user-country` DB, public-WAN-IP lookup (no leak)** | ✅ Implemented + verified offline (IPv4 `86.120.0.1`→RO, `8.8.8.8`→US, `1.1.1.1`→AU; IPv6 RO ranges→RO; behind-NAT skips) |
| **Last-known-good cache (`regdomain-lkg`) rung + WAN-change skip** | ✅ Implemented + tested (Rust + shell) |
| **DB staged on all 3 build paths (Containerfile / mkosi amd64 / arm64) + build-asserted** | ✅ Implemented |
| Runtime calibration oneshot service + systemd unit | 🟡 Implemented + wired (started at boot by `network-apply.sh` right after hostapd; shell verify-retry SM mirrors `next_rung_action`); gate-validated (T2 shellcheck/`bash -n` + T3 QEMU ordering, 2026-07-11); **not metal-run as a service** |
| Supervisor `--wifi-calibrate` subcommand routing rung rendering through the core | 🔴 Roadmap (not built) |
| Reconciler wiring (start/mask supplicant per role, trigger full re-calibrate on WAN change) | 🔴 Roadmap (contract defined by `supplicant_policy`) |
| Offline GeoIP DB end-to-end on-metal (public-WAN-IP path) as the boot unit | 🟡 Lookup + ladder proven offline on the dev box; not yet metal-run as the ordered unit |
| **W1 two-phase (boot fast-path + WAN-online re-resolve `hookprobe-regdomain-reresolve.service`)** | ✅ Implemented (`base/units/hookprobe-regdomain-reresolve.service`, `regdomain-apply.sh` re-resolve mode) + **T3 QEMU ordering gate PASSED** (2026-07-11: regdomain Finished BEFORE network-reconcile; reresolve After network-online; `unchanged (00) → no-op` proven live) |
| **W2 omit-`country_code`-when-unresolved fail-safe (never emit `=00`)** | ✅ Implemented (`wifi_cfg.rs:514` — `00` → omit `country_code`+`ieee80211d`) + T1 inverted unit tests green + **`hostapd -dd` dry-parse gate PASSED** (neg-control `country_code=00` fails distinctly at config-parse) |
| **W3 `pick_24_channel` 1/6/11 best-match** | ✅ Implemented (`wifi_calibrate.rs:746`) + T1 unit tests green (empty→6; congested-6→1/11; tie-break lowest) |
| **W4 verify-retry ladder run at boot + `next_rung_action` clean-retry-then-step-down** | 🟡 LOGIC implemented (`next_rung_action` `wifi_calibrate.rs:793` + `wifi-calibrate.sh` started after hostapd) + T1 green; **actual radio DFS bounce / clean-restart-holds-VHT80 still needs metal** |
| **AP iface `.network` `RequiredForOnline=no` (so `network-online.target` is reached)** | ⚠️→✅ **The earlier "✅ Implemented + T3-asserted" claim was FALSE — see BUG-N1 below.** The key was emitted in `[Network]`, where systemd **silently ignores it** (`Unknown key 'RequiredForOnline' in section [Network], ignoring`), so it never applied on real hardware: `wait-online` blocked on `wlan0: configuring`, FAILED, `network-online.target` never activated, every boot `degraded`. FIXED 2026-07-17 (emitted as a real `[Link]` section in `lan.rs`/`multi_wan.rs`) + section-asserting regression tests. Metal re-verify pending the v5 flash |
| **D24–D33 autonomous 5 GHz channel optimizer (survey→score→select→validate→commit/revert; DFS test-and-learn; channel-LKG; 03:00 timer; artifact)** | 🔴 Roadmap (SPEC-COMPLETE this change; pure core `wifi_calibrate.rs` fns + `wifi-optimize.sh`/`hookprobe-wifi-optimize@` unit/timer NOT built yet — code-developer implements after the D6 3-rung ladder fix lands; DFS-CAC seam `dfs_cac_seconds`/`select_settle_seconds` already exists) |
| DFS AP-mode actually works on brcmfmac FullMAC (the `dfs_ap_supported` learning) | ✅ **RESOLVED — it does NOT** (exhaustive EU matrix, Pi4+CM5 metal, 2026-07-17: all DFS 52–140 fail). **Live-proven on the running Pi4**: `iw reg get` = kernel `country RO: DFS-ETSI` but firmware `phy#56 country 99: DFS-UNSET` (the handoff failed), AP forced to ch40/80MHz UNII-1. Root-caused to the stock CLM blob (DFS-AP disabled; byte-identical to current upstream) + the #6669 firmware regdomain-reject bug — NOT a config bug on our side (see Extension RC-DFS). `dfs_ap_supported=false` is now seeded for brcmfmac; DFS-AP needs a SoftMAC USB radio |
| **D35–D44 calibration LEARNING MODEL (accumulating (radio,regdomain,channel,width) store; Beta-hold + EMA-congestion; quality/confidence; direct-to-best skip; known-bad+re-probe; UCB explore/exploit; discounted-Beta decay; supersedes band-LKG/channel-LKG/blocked_channels; `LearnDecision` artifact)** | 🔴 Roadmap (SPEC-COMPLETE this change; pure core `wifi_calibrate.rs` fns NOT built yet — code-developer implements; reuses `verify_rung`/`Stability`/`RegChannels`/`RadioCaps`/`BlockSurvey`/`select_settle_seconds`/D25 timer/D29 loop unchanged). Convergence/anti-flap/always-joinable are unit-testable off-metal; the learning-curve on real brcmfmac is the CM5/Pi5 metal gate |

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD.** The pure decision core (`wifi_calibrate.rs` — regdomain-from-WAN-exit, 5GHz-first ladder, survey optimizer) is reusable Rust; everything that drives `iw reg set` / hostapd / `wpa_supplicant` / cfg80211-nl80211 / brcmfmac is re-implemented on heqk's WiFi control surface. heqk's CYW43455 bring-up (through AP-scan; P10 D/E pending) must expose an equivalent AP-control surface. → **Parallel WiFi track** (heqk P10).
