# Cyber Resilience Act (Regulation (EU) 2024/2847): matrix (gate G3)

Draft. Statuses are defined in [`README.md`](README.md). **No row is compliant.** Annex text below is
quoted (abridged) from the EUR-Lex text; application dates are in the README (full application 11 December
2027; art. 14 reporting since 11 September 2026).

## 1. Classification and conformity route (LEGAL, decide first)

Annex III lists (verbatim entries from the EUR-Lex text):

- Class I, item 11: "Operating systems"
- Class I, item 12: "Routers, modems intended for the connection to the internet, and switches"
- Class I, item 6: "Network management systems"; item 7: "Security information and event management (SIEM) systems"; item 5: "Products with digital elements with the function of virtual private network (VPN)"; item 8: "Boot managers"
- Class II, item 2: "Firewalls, intrusion detection and prevention systems"

Recital 45 (EUR-Lex): firewalls and intrusion detection/prevention systems are class II when "defined by
their core functionality" as such; products that merely integrate a firewall or IDS/IPS are not covered by
that class on that ground alone.

| # | Question for legal | Why it matters | Evidence for the discussion |
|---|---|---|---|
| Q1 | Is the gateway's **core functionality** a firewall / IDS-IPS (class II) or a router (class I)? | Class II: third-party assessment mandatory (art. 32(3): module B+C, module H, or an EUCC-type scheme at "substantial" or higher). Class I: module A only if harmonised standards / common specs / certification are applied in full (art. 32(2)) | Project positioning: `README.md`, `SECURITY.md` ("AI-native security operating system", IDS/IPS, enforcement), ADR 0023, ADR 0047. Marketing that leads with IDS/IPS supports class II |
| Q2 | Is the heqk OS, distributed separately (AGPL + commercial, `LICENSING.md`), a separate product with digital elements (class I "Operating systems")? Is that distribution a commercial activity? | Determines whether the software release needs its own conformity assessment and DoC | `LICENSING.md`, `os/kernel/LICENSING.md`, GitHub releases (`release.yml`) |
| Q3 | Do the Commission's implementing technical descriptions of the Annex III categories (art. 7(4)) change Q1? | The descriptions narrow or widen category scope | Not read (adoption status / reference not verified here) |
| Q4 | Does art. 69(3) make art. 14 reporting apply already to devices or software already on the EU market? | Reporting is live since 11 Sept 2026 | See README |
| Q5 | Which harmonised standards under the CRA exist for the chosen class at the time of assessment? | No CRA harmonised standard is cited in this package; EN 18031 is a RED standard | None |

## 2. Annex I part I (essential cybersecurity requirements of the product)

| Ref | Requirement (abridged) | Repo evidence (exists) | Still required | Status |
|---|---|---|---|---|
| I(1) | Appropriate cybersecurity based on risks | ADRs 0023, 0043, 0044, 0047, 0050, 0051; audit `docs/design/heqk-audit-2026-11-10.md` | **Cybersecurity risk assessment (art. 13(2)) document: GAP** | GAP |
| I(2)(a) | No known exploitable vulnerabilities at placing on market | cargo-deny RustSec + npm audit (gate g4: `tools/ci/gates.sh`, `tools/ci/deny.toml`, `.github/workflows/ci.yml`, `nightly.yml`); fuzzing (`docs/design/fuzz-evidence.md`); code-scanning triage (`docs/security/code-scanning-triage-2026-11-08.md`) | Release-time vulnerability report against the final SBOM incl. firmware blob; CYW43455 firmware vulnerability status unknown (vendor binary); penetration test; tracked dev AK private keys (`os/kernel/hboot/src/attest_keys.rs`, audit §2.1 #8) must be excluded/rejected | PARTIAL |
| I(2)(b) | Secure by default, with reset to original state | No default password (`mcauth.rs`); per-device AP credential (`apcred.rs`, ADR 0054); WPA2 default, WPA3 opt-in (`wificfg.rs`); factory reset (`factoryreset.rs`, REL-09 metal PASS) | Plain HTTP until a certificate is provisioned (ADR 0051 D3); apcred needs OTP (TC-02); legal view on WPA2-as-default | PARTIAL |
| I(2)(c) | Vulnerabilities addressable through security updates, incl. automatic updates by default with opt-out where applicable | Signed A/B OS update with trial/rollback (`otaimg.rs`, `ota.rs`, OTA-01/02 metal); signed data packs (`upload.rs`, ADR 0056) | **GAP: updates are owner-uploaded only; no automatic update or update notification mechanism** (searched `kernel/src`). No update distribution service. Key custody TC-01 blocked | GAP |
| I(2)(d) | Protection from unauthorised access; report possible unauthorised access | Owner session, re-auth, CSRF/Origin/replay guards (`http.rs`, `actionapi.rs`, `ownerapi.rs`); login throttle (`mcauth.rs`) | Authentication events are not logged persistently (see I(2)(l)); UART console analysis | PARTIAL |
| I(2)(e) | Confidentiality of stored/transmitted data (encryption at rest/in transit) | `seal.rs` HQKSEAL1; `evlog.rs` sealed; TLS 1.3 PQ hybrid (ADR 0051) | Synthetic SRK without OTP (`seal.rs` security limit); WIFI.TXT PSK cleartext; plaintext syslog (`siem.rs`) and webhook (`alerthook.rs`) | PARTIAL |
| I(2)(f) | Integrity of stored/transmitted data, programs, configuration | Signed boot image, signed POLICY/WAN/WIFI and packs (`policysig.rs`, ADR 0058), HMAC-chained journal (`ownerjournal.rs`), pinned anchor (`anchor.rs`) | SEC-3 fuses (TC-03) and RPMB (TC-04) undecided; HBoot bytes not covered by the payload signature (`otaimg.rs` check 4) | PARTIAL |
| I(2)(g) | Data minimisation | MAC pseudonymisation in RA-rule export (`export.rs`); SIEM export off until the operator configures it (`siem.rs`) | Data inventory and retention statement: GAP | PARTIAL |
| I(2)(h) | Availability of essential functions, also after an incident; DoS resilience | Watchdog, crash record, rollback (REL-01/02, OTA-02); enforcement separation (ADR 0023); rate limiting (`ratelimit.rs`) | REL-05..08 open (soak, thermal, scale, Wi-Fi TX-stall root cause) | PARTIAL |
| I(2)(i) | Minimise negative impact on other devices/networks | Observe-by-default, drop only genuine attacks (ADR 0023); alert storm limits (`alerthook.rs`) | DET-01 false-positive corpus not collected | PARTIAL |
| I(2)(j) | Limit attack surfaces incl. external interfaces | Small service set (Mission Control, DHCP, DNS, AP); bare-metal OS; EL0 parser isolation (ADR 0050 D4 steps 1, 2a) | SEC-01 remaining steps; interface inventory (see `en18031-matrix.md` §2); BT radio off-state confirmation | PARTIAL |
| I(2)(k) | Reduce incident impact (exploitation mitigation) | Capability microkernel (ADR 0043), EL0 excursions for TLS/DNS/Wasm (ADR 0050, M5.5) | SEC-01; independent review | PARTIAL |
| I(2)(l) | Record and monitor relevant internal activity (access, modification), with user opt-out | Detections sealed (`evlog.rs`); config changes and artifact activations in journal (`ownerjournal.rs`) | **GAP: no persistent record of authentication / access events**; no documented opt-out | PARTIAL |
| I(2)(m) | Securely and easily remove all data and settings permanently; secure transfer | Factory reset (`factoryreset.rs`, metal 9/9) | eMMC remanence analysis; boot-partition files (PSK, cert) not erased; no settings export/transfer | PARTIAL |

## 3. Annex I part II (vulnerability handling) and related obligations

| Ref | Requirement (abridged) | Repo evidence (exists) | Still required | Status |
|---|---|---|---|---|
| II(1) | Identify/document components and vulnerabilities, incl. an SBOM in a machine-readable format covering at least top-level dependencies | CycloneDX SBOM per lockfile in gate g4 (`tools/ci/gates.sh` lines ~166-175, completeness check); release SBOM `sbom-<tag>.cdx.json` from `syft scan dir:.` (`.github/workflows/release.yml`) | **Verify the release SBOM lists the CYW43455 firmware .bin, CLM blob and NVRAM** (they are gitignored, not packages; a directory scan is unlikely to catalogue them; see `firmware-provenance.md`). SBOM of the exact signed image (vs repo directory). CBOM claimed in `SECURITY.md`, generator not found | PARTIAL |
| II(2) | Remediate without delay, incl. security updates | OTA path (above); dependabot (`.github/dependabot.yml`); autoheal loop (`.github/workflows/autoheal.yml`, ADR 0052 CI/CD, proposed) | Documented remediation SLA; update distribution | PARTIAL |
| II(3) | Regular security testing and review | QEMU gates `os/kernel/validate.sh`, `os/kernel/tools/mc-e2e.sh`, fuzzing, metal batches `docs/design/metal-evidence/` | Third-party testing; documented review cadence | PARTIAL |
| II(4) | Publicly disclose fixed vulnerabilities (advisories) | `SECURITY.md` (synchronised fix + advisory) | Advisory publication process and location (none published yet); VEX for heqk (pipeline ADR 0024 is legacy Linux tier) | PARTIAL |
| II(5) | Coordinated vulnerability disclosure policy | `SECURITY.md` (private reporting, 3/10 business-day targets, ≤ 90-day window, safe harbour) | **Contact address marked "operator: confirm/replace"** in `SECURITY.md`; PGP key "when available" | PARTIAL |
| II(6) | Facilitate vulnerability information sharing; contact address | `SECURITY.md` | Confirmed contact; single point of contact for users (art. 13(17)) | PARTIAL |
| II(7) | Secure distribution of updates | Signed images (hybrid Ed25519 + SLH-DSA), SLSA provenance + SHA256SUMS on draft releases (`release.yml`) | Offline signing ceremony / key custody (TC-01); a customer update channel | PARTIAL |
| II(8) | Disseminate security updates without delay, free of charge, with advisory messages | None beyond `SECURITY.md` | Process + channel | GAP |
| Art. 13(8) | Support period ≥ 5 years unless shorter expected use; stated to the user | `SECURITY.md`: "current release channel and the most recent prior release" | **GAP: no support period in years / end date defined** | GAP |
| Art. 14 | Report actively exploited vulnerabilities and severe incidents via the ENISA single reporting platform: early warning ≤ 24 h, notification ≤ 72 h, final report ≤ 14 days after a fix is available (vulnerabilities) | None | **GAP: no reporting procedure, roles, CSIRT-coordinator identification or platform account**. Possibly already a live obligation (README Q4) | GAP |
| Art. 13(5) / due diligence | Due diligence on third-party components (incl. firmware) | cargo-deny sources/licences policy (`tools/ci/deny.toml`); pinned firmware hash (`tools/ci/stage-firmware.sh`) | Vendor security-support commitment for the CYW43455 firmware; see `firmware-provenance.md` | PARTIAL |
| Annex II / VII | User information and technical documentation | None | GAP | GAP |
| Art. 28 / 30 | EU DoC, CE marking | None | After conformity assessment | GAP |
