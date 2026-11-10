# EN 18031-1/-2/-3: requirement-area matrix (gate G1, RED art. 3(3)(d)(e)(f))

Draft. Statuses are defined in [`README.md`](README.md). **No row is compliant.** "EEP" means the
engineering evidence exists; the EN 18031 assessment by a laboratory (and a notified body where required)
is still outstanding for every row.

Mechanism codes (ACM, AUM, SUM, SSM, SCM, RLM, NMM, TCM, CCK, CRY, GEC, LGM, DLM, UNM) are the EN 18031
mechanism families as summarised in public material. The standards were **not** read (paywalled): the
compliance lead must map each row to the exact clause numbers and decision trees of the purchased text.

## 1. Which parts apply (LEGAL to confirm)

| Part | RED article | Applies to | Our position |
|---|---|---|---|
| EN 18031-1 | 3(3)(d) network harm | Internet-connected radio equipment | **Applies** (Wi-Fi AP/STA + Internet router) |
| EN 18031-2 | 3(3)(e) personal data / privacy | Internet-connected radio equipment that processes personal data (also toys, childcare, wearables) | **Expected to apply**: the device processes client MAC addresses, IP addresses, DHCP host names, DNS queries and per-device detections (`os/kernel/kernel/src/evlog.rs`, `shield.rs`, `discovery.rs`) |
| EN 18031-3 | 3(3)(f) fraud / monetary transfer | Internet-connected radio equipment enabling transfer of money, monetary value or virtual currency | **N/A (justify)**: no payment or value-transfer function found in `os/kernel/kernel/src` (searched "payment", "wallet", "currency"). Commercial licensing is outside the device. Legal to confirm |

Restrictions in Implementing Decision (EU) 2025/138 that matter here (from public summaries; verify in the
OJ text): (1) no presumption of conformity for 3(3)(d)/(e)/(f) where the standard's password provisions let
the user choose not to set or use a password; (2) "rationale"/"guidance" parts give no presumption; further
part-specific restrictions exist (e.g. for -2 parental-control and -3 related items). heqk has no
user-optional password (see AUM below), but the lab must confirm no restriction is triggered; if one is,
the route is EU-type examination by a notified body, not module A self-assessment.

## 2. Assets and interfaces (input to the assessment; PARTIAL)

| Interface | Code | Exposure | Note |
|---|---|---|---|
| Mission Control HTTP :80 / HTTPS :443 | `mcserve.rs`, `http.rs`, `tlshost.rs` | LAN / management network | Plain :80 serves the UI until a TLS certificate is provisioned; afterwards :80 only redirects (`mcserve.rs` line ~880, ADR 0051 D4) |
| Wi-Fi AP (WPA2/WPA3) | `apcore.rs`, `os/kernel/sae/`, `arch-aarch64/src/wpa.rs` | Radio | Per-device setup credential (`apcred.rs`) |
| DHCP / DNS server (Shield) | `lansvc.rs`, `dnssink.rs`, `shield.rs` | LAN | DNS parser moved to EL0 (ADR 0050 step 2a); DHCP still EL1 (release gate SEC-01) |
| WAN (DHCP/PPPoE/IPv6, SNTP) | `netcfg.rs`, `wanntp.rs`, `wanhealth.rs` | Internet | Parsers in EL1 (SEC-01 open) |
| Control channel (Noise IK + ML-KEM) | `securechannel.rs`, `enroll.rs` | Optional, operator | |
| Boot partition files (POLICY/WAN/WIFI/OWNER/MCTLS) | `policysig.rs`, `wificfg.rs`, `mcauth.rs` | Physical | |
| UART console | `main.rs` (UART0 console) | Physical (debug header) | **GAP**: no document states what the console accepts in a production build; needed for GEC/ACM debug-interface analysis |
| Bluetooth (same CYW43455) | `arch-aarch64/src/bt.rs`, feature `p10bt` | Radio | Not in the shipped flavours (`os/kernel/kernel/Cargo.toml`: `p10bt` is opt-in). Lab to confirm the BT radio stays off |

**GAP**: a single asset / interface inventory with security and network assets classified the way EN 18031
requires does not exist. The table above is a starting point only.

## 3. EN 18031-1 (art. 3(3)(d)) and shared mechanisms

| Area | Requirement summary | Repo evidence (exists) | Still required | Status |
|---|---|---|---|---|
| ACM access control | Security/network assets accessible only to authorised entities | Every route except `/login`, `/api/login`, `/api/logout`, minimal `/api/health` needs the owner session (`os/kernel/kernel/src/http.rs`, audit `docs/design/heqk-audit-2026-11-10.md` §1 row 13); strict Origin, CSRF, per-session sequence + replay floor, owner re-auth on every write (`actionapi.rs`, `ownerapi.rs`; phases `[P-actions]`, `[P-seq-floor]`, `[P-write-rate]`; metal `os/kernel/tools/actions-metal.sh` per audit); unclaimed device refuses all protected routes (`mcauth.rs` header). Signed configuration: POLICY/WAN/WIFI verified before parsing (`policysig.rs`, `wificfg.rs`, ADR 0058, `docs/design/adr0058-implementation.md`, `[P-policy-sig]`, `[P-wansig]`) | Lab assessment; UART/debug-interface analysis; written access-control policy per asset | PARTIAL |
| AUM authentication | No default/universal passwords; credential strength; brute-force protection | No default password: 128-bit owner token minted at flash, only `sha256(salt‖token)` stored in `OWNER.TXT` (`mcauth.rs`; `os/build/make-cm5-heqk-disk.sh`). Per-source + global login throttle (`mcauth.rs` `GLOBAL_LOGIN_FAILS`, audit §3.1 A5). Per-device Wi-Fi setup credential `HKDF(SRK,"HQ-AP-SETUP")` (`apcred.rs`, ADR 0054, `[P-apcred]`); release + factory refuse a bench PSK (`release.yml`, audit §2.1 #7). WPA3-SAE + PMF metal-proven (`docs/design/metal-evidence/20261110-batch38-47.md` "WPA3: PASS (6/6)") | **apcred depends on a real SRK: with blank OTP it returns None** (no per-device AP credential), and OTP provisioning is the open production blocker TC-02. Owner-token handling at the factory (how shown once, how stored by the owner) is a manufacturing procedure: not written. Lab confirms no 2025/138 password restriction is triggered. WPA2 remains the default (WPA3 opt-in) | PARTIAL |
| SUM secure update | Updates authenticated, integrity-protected, anti-rollback | Hybrid Ed25519 + SLH-DSA boot image signing (`os/build/heqk-sign`, `os/kernel/boot-abi/src/verify.rs`); OS image upload verified with the shared boot verifier + SVN floor before any slot write, A/B trial with commit-on-health and rollback (`otaimg.rs`, `ota.rs`; phases `[P15-otaimg]`, `[P-otaverify]`, `[P-abslot]`; metal `docs/design/metal-evidence/20261110-ota-a1.md`, `20261110-batch29.md` "OTA-ROLLBACK: PASS"); signed data packs with anti-rollback (`upload.rs`, `artstore.rs`, ADR 0056) | Production signing-key custody (TC-01, blocked); pack anti-rollback is relative after erase (audit §2.1 #2, open); HBoot changes need USB reflash (`otaimg.rs` check 4). No automatic update check (see UNM). Lab assessment | PARTIAL |
| SSM secure storage | Stored security assets protected (integrity, confidentiality where needed) | `HQKSEAL1` encrypt-then-MAC sealing bound to boot measurement (`seal.rs`); owner journal HMAC chain under `HKDF(SRK,…)` (`ownerjournal.rs`); sealed evidence log (`evlog.rs`); EL2 stage-2 carve keeps EL1 from reading OTP (SEC-2, memory/metal record); device-pinned trust anchor (`anchor.rs`, `[P-anchor]`) | **`seal.rs` states that without OTP the kernel uses a SYNTHETIC SRK** and measurement binding is not real; OTP provisioning is blocked (TC-02). No RPMB anchoring (TC-04, owner decision). SEC-3 secure-boot fuses undecided (TC-03). Software attestation-key private keys tracked in git (`os/kernel/hboot/src/attest_keys.rs`, audit §2.1 #8). Wi-Fi PSK is cleartext on the boot partition (`wificfg.rs` header, acknowledged) | GAP until TC-02 closes |
| SCM secure communication | Communication of security/network assets protected with best-practice crypto | TLS 1.3 only, X25519MLKEM768 preferred, ECDSA P-256 cert, terminated in an isolated EL0 server (ADR 0051, `tlshost.rs`; metal `tools/diagnostics/cm5-tls-pq-check.mjs` per audit §1 row 4); Noise IK + ML-KEM-768 control channel (`securechannel.rs`) | **Before a certificate is provisioned Mission Control (incl. the owner login token) runs over plain HTTP** (ADR 0051 D3/D4); certificate provisioning is offline/manual (audit §1 row 4). Owner alert webhook is plain HTTP with HMAC (integrity only) (`alerthook.rs`); SIEM export is plaintext UDP syslog (`siem.rs`). Crypto primitive audit gaps listed in ADR 0051 D1 table. Lab assessment | PARTIAL |
| CCK confidential cryptographic keys | Keys generated/stored/protected appropriately; no hard-coded shared secrets | Per-device keys derived from SRK (TLS key `HKDF(SRK,"heqk-mc-tls-p256")` ADR 0051 D3; AP credential; journal/evidence keys); TLS private scalar re-derived and zeroised (audit §2.1 #6) | Same SRK dependency as SSM. Tracked dev AK keys in git (audit #8). Placeholder Broadcom NVRAM `macaddr` inserted at staging (`os/kernel/cm5-boot/stage-wifi-firmware.sh`): not a key, but confirm it is always overridden | GAP until TC-02 closes |
| CRY cryptography | Best-practice algorithms | ADR 0002 (crypto agility / PQC); ADR 0051 D1 primitive table; KATs in `securechannel.rs` | Lab review; CBOM: `SECURITY.md` claims "CBOM per image" but no heqk CBOM generator was found in `os/build`, `tools`, `.github` (only references in `os/kernel/validate.sh` and design docs) | PARTIAL |
| RLM resilience | Resilience against DoS on the device's own functions | Watchdog armed after trial confirm (`rtwdog.rs`, `[P-rtwdog]`, metal batch29 "WDOG] armed=true"); crash record (REL-02); bounded excursions for EL0 TLS (ADR 0050 D5); NAT table bounded/hashed (audit §3.1 A7); rate limiter (`ratelimit.rs`); enforcement separation keeps legit traffic flowing (ADR 0023); power-loss torture (REL-04 batch30) | Release gate REL-05 (72 h soak), REL-06 (thermal), REL-07 (client scale), REL-08 (Wi-Fi TX-stall root cause) all open. Lab DoS testing | PARTIAL |
| NMM network monitoring | (For network equipment) monitor and detect attacks | IDS rules + Wasm detections (ADR 0050, `rules.rs`, `rulepack.rs`, `wasmhost.rs`); detection benchmark `docs/design/heqk-detection-benchmark-2026-11-09.md` | DET-01 benign false-positive corpus not collected. Lab to decide applicability per decision tree | PARTIAL |
| TCM traffic control | (For network equipment) control traffic between networks | NAT/forwarding, per-device reach segmentation (`segment.rs`), device policy (`devpolicy.rs`), Shield DNS levels (ADR 0057, metal 12/12), management floor in signed WAN.TXT (TC-07, metal batch31-32) | Default-policy documentation for the user; lab assessment | EEP |
| GEC general equipment capabilities | No known exploitable vulnerabilities; minimised exposed services; robust input handling | Fuzzing of network parsers (`docs/design/fuzz-evidence.md` "FUZZ: PASS (300s per target)", release gate SEC-02); cargo-deny RustSec + SBOM gate g4 (`tools/ci/gates.sh`, `tools/ci/deny.toml`); code-scanning triage (`docs/security/code-scanning-triage-2026-11-08.md`); EL0 isolation of TLS/HTTP/DNS parsers (ADR 0050) | SEC-01 open (DHCP, WAN control, Noise, WPA authenticator parsers still EL1). Owner-journal replay + upload form handlers lack a host fuzz target (audit §2.1 #10). Debug interface analysis (UART). External penetration test: GAP | PARTIAL |

## 4. EN 18031-2 additions (art. 3(3)(e), personal data)

| Area | Requirement summary | Repo evidence (exists) | Still required | Status |
|---|---|---|---|---|
| Personal-data inventory | Identify personal data processed/stored | Code shows: client MAC/IP, DHCP names, device labels (`ownerjournal.rs` `Kind::DeviceLabel`), DNS decisions, detections with device ids (`evlog.rs`), syslog export (`siem.rs`) | **GAP**: no data inventory / privacy notice. Legal (GDPR controller analysis: owner vs manufacturer) | GAP |
| Data minimisation in exports | | MAC-derived sources in exported RA rules pseudonymised `HMAC(HKDF(SRK,"HQ-MAC-PSEUDONYM"))` (`export.rs` ~line 82) | Scope is RA rules only; other exports not reviewed. SRK dependency | PARTIAL |
| LGM logging | Log security-relevant events; protect logs | Sealed evidence ring (`evlog.rs`, metal `tools/diagnostics/cm5-evlog-check.sh` per audit); owner journal records config changes and artifact activations (`ownerjournal.rs` `Kind` list) | **GAP: no persistent log of authentication events** (login success/failure, session creation, re-auth failures): not found in `events.rs`, `evlog.rs`, `ownerjournal.rs`, `mcauth.rs`. Journal tail truncation indistinguishable from torn write (audit §2.1 #5) | PARTIAL |
| DLM deletion | User can delete personal data | Factory reset erases evidence ring, artifact manifest, snapshot, enrolled owner key, then owner journal, power-cut safe (`factoryreset.rs`, ADR 0055; release gate REL-09; metal `docs/design/metal-evidence/20261110-batch38-47.md` "FACTORY-RESET: PASS (9/9)") | Physical-media analysis (eMMC wear-levelling: zeroed sectors vs remanence) by lab; boot-partition files (WIFI.TXT PSK, MCTLS.CRT) not erased by design (`factoryreset.rs` "never touched") — document for the user | PARTIAL |
| UNM user notification | Notify the user of changes affecting personal data / security (e.g. updates) | Owner alert webhook (`alerthook.rs`, DET-03, metal batch34-35); Mission Control incident feed | **GAP**: no notification that a security update is available (no update-availability check found; search "update available", "auto.?update" in `kernel/src`: no hits) | GAP |
| ACM/AUM/SSM/SCM/CCK for personal data | As section 3, applied to personal-data assets | As section 3 | As section 3; plain-HTTP-before-certificate exposes device inventory on the LAN | PARTIAL |

## 5. EN 18031-3 (art. 3(3)(f))

N/A (justify): no function enables transfer of money, monetary value or virtual currency. Legal to confirm.

## 6. Cross-cutting gaps for G1

1. Product cybersecurity risk assessment and EN 18031 decision-tree records per mechanism: GAP.
2. Production trust root (OTP, TC-02) blocks SSM/CCK/AUM evidence on a shipped unit: GAP.
3. Technical documentation folder, DoC, user security information: GAP.
4. Third-party penetration test of the release build: GAP.
5. Assessment of 2025/138 restrictions by the lab, and route decision (module A vs notified body): LEGAL/LAB.
