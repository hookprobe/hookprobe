# HookProbe heqk: compliance evidence package

**Status: DRAFT working file. Nothing in this package is compliant, certified, approved or signed off.**
This package maps regulatory requirements to the engineering evidence that exists in this repository and
lists what is still required from a test laboratory, a notified body, a TCB, legal counsel or manufacturing.
It is input for those parties. It is not a declaration of conformity and must not be used as one.

Product under assessment: a home/SMB security gateway built on a Raspberry Pi Compute Module 5 (BCM2712)
running heqk, a bare-metal Rust OS (`os/kernel/`). Functions: Wi-Fi access point on the module's CYW43455
radio (WPA2 default, WPA3-SAE opt-in), Wi-Fi station mode, Ethernet WAN router with NAT/PPPoE/IPv6,
IDS/IPS with enforcement, DNS protection ("Shield"), and the on-device web UI "Mission Control" served over
HTTPS (ADR 0047, ADR 0051). Shipped build flavours: `prod-mc` and the AP image
(`hboot,apmc,wifi-bigtx,appersist`), built by `.github/workflows/release.yml`.

## Status vocabulary (used in every matrix)

| Status | Meaning |
|---|---|
| **EEP** | Engineering evidence present (code + gate or metal record cited). Lab / notified-body / legal sign-off still required. Not "compliant". |
| **PARTIAL** | Some engineering evidence exists; a named engineering gap remains, plus the sign-off above. |
| **GAP** | No evidence found in the repository (searched; search terms given where useful). |
| **LAB** | Laboratory measurement item. No test report exists in the repository. |
| **LEGAL** | Requires a legal / regulatory determination before any engineering status means anything. |
| **N/A (justify)** | Believed not applicable, with the reason. Legal must confirm the justification. |

Rule (operator): an implementation, a passing QEMU gate, a metal run or a passing CI scan **never** closes a
release gate on its own. Manufacturing, legal and laboratory items close only with that party's evidence,
recorded as an operator sign-off under `docs/release/signoffs/` (see below).

## The four gates

| Gate | Legal basis | File | Closes when |
|---|---|---|---|
| G1. EU RED cybersecurity | Directive 2014/53/EU art. 3(3)(d), (e), (f), activated by Delegated Regulation (EU) 2022/30 (as amended by (EU) 2023/2444; mandatory from 1 August 2025). Harmonised standards EN 18031-1/-2/-3:2024, cited with restrictions by Implementing Decision (EU) 2025/138 | [`en18031-matrix.md`](en18031-matrix.md) | Lab assessment report against EN 18031 (and, if any restriction is triggered or a clause is not applied in full, a notified-body EU-type examination certificate), signed technical file, DoC |
| G2. EU RED radio / EMC / safety | Directive 2014/53/EU art. 3(1)(a), 3(1)(b), 3(2) | [`red-radio.md`](red-radio.md) | Accredited lab test reports (safety, EMC, radio, RF exposure) for the finished product in its enclosure with its antenna, plus module-vendor documentation |
| G3. EU Cyber Resilience Act | Regulation (EU) 2024/2847 | [`cra-matrix.md`](cra-matrix.md) | Legal classification (Annex III class), conformity-assessment route completed (notified body if class II, or class I without full harmonised-standard application), vulnerability-handling process operating, reporting channel to ENISA/CSIRT ready |
| G4. FCC (separate market-entry gate) | 47 CFR Parts 2 and 15 | [`fcc-gate.md`](fcc-gate.md) | TCB/lab decision on modular-approval reliance or a new grant, host-product testing, labelling. Independent of the EU gates; passing one never implies the other |
| Cross-cutting: firmware provenance | Redistribution licence of the CYW43455 firmware, CLM and NVRAM | [`firmware-provenance.md`](firmware-provenance.md) | Legal sign-off `firmware-licence` (release-gate item CMP-02) |

### CRA application dates (verified against the EUR-Lex text of Regulation (EU) 2024/2847, art. 71)

| Date | What applies |
|---|---|
| 10 December 2024 | Entry into force (20th day after publication in the OJ of 20 November 2024) |
| 11 June 2026 | Chapter IV (arts. 35 to 51), notification of conformity assessment bodies |
| **11 September 2026** | **Art. 14 reporting obligations (actively exploited vulnerabilities, severe incidents). Already in force on the date of this draft (2026-11-10).** |
| 11 December 2027 | Full application (Annex I essential requirements, conformity assessment, CE marking under the CRA) |

Open legal question: art. 69(3) is understood to extend the art. 14 reporting duty to products placed on the
market before 11 December 2027. If any heqk device or heqk software release is already "made available on
the market" in the EU (including as a commercially licensed AGPL download, see `LICENSING.md`), reporting may
already be a live obligation. Legal to confirm.

Open legal question: the relationship between the RED delegated act (EU) 2022/30 and the CRA after
11 December 2027 (repeal or transition of the RED cybersecurity requirements for products also in CRA
scope). Not verified here; legal to confirm.

## What a gate sign-off needs

A gate closes only with all of the following, filed in the technical documentation and referenced from an
operator sign-off file:

1. The matrix in this package with every row either closed by third-party evidence or justified N/A.
2. The third-party evidence itself (test reports with lab accreditation scope, notified-body or TCB
   certificates, legal opinions). Repository evidence (code, `os/kernel/validate.sh` phases,
   `docs/design/metal-evidence/`, `tools/release-gate/check.py` output) is supporting material only.
3. The exact build the evidence applies to: image sha256 and git commit (`os/build/make-cm5-heqk-disk.sh`
   writes `<image>.json` with `sha256`, `git`, `features`, `svn`), the firmware hashes from
   `firmware-provenance.md`, and the SBOM from `release.yml`.
4. A risk assessment (RED: EN 18031 requires a documented assessment of each mechanism's applicability;
   CRA: art. 13(2) cybersecurity risk assessment). **GAP**: no product-level cybersecurity risk assessment
   document exists in the repository (searched `docs/` for "risk assessment", "threat model" at product level).
5. User information: instructions, security information, support period, DoC (RED art. 10(8)/(9); CRA
   Annex II). **GAP**: none drafted.

## Who signs (roles only)

| Role | Signs |
|---|---|
| Release owner (operator) | Writes the sign-off files in `docs/release/signoffs/` (only the operator writes these; see that folder's README). Agents never create or edit them |
| Compliance lead | Owns this package; confirms every row's evidence reference is current for the release build |
| Product security lead / PSIRT owner | CRA Annex I part II process, CVD (`SECURITY.md`), art. 14 reporting readiness |
| Accredited test laboratory | RED 3(1)(a)/(b), 3(2) reports; EN 18031 assessment report; FCC Part 15 test reports |
| EU notified body | RED EU-type examination where required; CRA module B/H where required |
| FCC TCB | Grant or permissive-change decision |
| Legal counsel | CRA class, firmware redistribution (CMP-02), AGPL/commercial distribution, art. 69(3) question, DoC wording |
| Manufacturing / quality lead | Factory provisioning (OTP, keys, labels), production control (RED module A / CRA module A or C), serial traceability |
| Module vendor (external) | CM5 module radio approvals, NVRAM/firmware integration conditions (input, not a sign-off) |

## Release-gate linkage

`tools/release-gate/items.txt` already carries the compliance items as blocked sign-offs:

- `CMP-01 | compliance | CE/RED + EN 18031, FCC, CRA SBOM / CVD / support period | signoff:certification`
- `CMP-02 | compliance | CYW43455 firmware redistribution terms | signoff:firmware-licence`

Recommendation (for the operator, not done here): split CMP-01 into one item per gate (G1 to G4) so that an
FCC grant cannot be read as closing an EU item and vice versa. Several trust-chain items are preconditions
for the cybersecurity gates and are themselves blocked: TC-01 key custody, TC-02 OTP provisioning
(production blocker, `docs/design/heqk-decision-record-otp-rpmb-2026-11-10.md`), TC-03 SEC-3 secure-boot
fuses, TC-04 RPMB.

## Sources consulted (public texts)

- Regulation (EU) 2024/2847, EUR-Lex: https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng (arts. 13, 14, 32, 71; Annexes I, III; recitals 45, 56, 60)
- Implementing Decision (EU) 2025/138 (EN 18031 citation with restrictions): secondary summaries only
  (e.g. https://www.ezurio.com/resources/blog/understanding-eu-commission-implementation-of-decision-eu-2025-138-new-harmonized-standards-and-restrictions,
  https://www.sgs.com/en/news/2025/02/safeguards-02625-eu-harmonizes-en-18031-standards). The OJ text and the
  Commission guidance on the restrictions must be read by the compliance lead.
- EN 18031-1/-2/-3 themselves are paywalled and were **not** read; clause references in the matrix are
  mechanism-level and must be checked against the purchased standard.
