# CodeQL code-scanning triage — 2026-11-08

328 open alerts (CodeQL default setup: actions, c-cpp, js/ts, python, rust) were triaged one by
one. **90 % sat in `legacy/`**; the live tree (`os/`, `onboarding/`, `tools/ci`) had 32, of which
none was a real vulnerability. Real defects were found and fixed in the V1 Python/JS that still
runs on the Fortress box (see the V1 section). Every dismissal below carries this evidence as its
GitHub comment.

| Area | Alerts | Disposition | Evidence |
|---|---|---|---|
| `legacy/v1/` (Python/JS, still deployed) | 143 | **fixed** where real; triage per alert | stack traces to HTTP clients, secrets in logs, DOM XSS, … — see below |
| `os/kernel/**`, `onboarding/…/responder-sim` — `rust/hard-coded-cryptographic-value` | 30 | false positive | see "heqk" |
| `legacy/linux-tier/crates/hookprobe-manifest` — `rust/cleartext-logging` | 11 | used in tests | all inside `#[test]` fns; the "passphrase" is the dummy literal `appass1234` in an `assert!` message |
| `legacy/linux-tier/base/drivers/rtl*` (vendored Realtek) | 142 | won't fix (third-party) / false positive | see "vendored drivers" |
| `tools/ci/heal/classify.py` — `py/weak-sensitive-data-hashing` | 2 | **fixed** | failure-signature hash SHA-1 → SHA-256 (no security role, but clean) |

## heqk — `rust/hard-coded-cryptographic-value` (30)
Each alert was read in context. None is a key, nonce or salt used in production:
- **Zero-initialised buffers overwritten before use** — `seal.rs:132/180` (nonce = H(domain‖seq‖t)),
  `fslog.rs:255/373/401`, `prodfull.rs:160`, `main.rs:4575/4601`, `mcauth.rs:51`, `boot-abi/sha256.rs:129`.
- **Known-answer tests** — `securechannel.rs:342` (RFC 8439 §2.8.2 ChaCha20-Poly1305 KAT key).
- **HKDF domain-separation labels** (the correct use of a constant salt) — `securechannel.rs:434`
  (`HEQK-HYBRID-KEX-v1`), `export.rs:94` (`HQ-MAC-PSEUDONYM`).
- **Self-test vectors** — `attest_svc.rs:114/115`, `main.rs:5653/5654`, `edge.rs:421-429`,
  `enroll.rs:1138-1515`, `export.rs:523/643`, `responder-sim/main.rs:213`: all use
  `test_vectors()`, which is `#[cfg(feature = "securechannel-selftest")]`, and a `compile_error!`
  refuses that feature on the metal target (entropy.rs / securechannel.rs).
- **Not cryptographic** — `mcserve.rs:337` (SNTP request id).

Design note kept open (not a CodeQL finding): `seal.rs` derives the AEAD nonce from
(domain, seq, t); uniqueness relies on the persisted sequence never rolling back under the same key.

## Vendored Realtek drivers (142)
`legacy/linux-tier/base/drivers/rtl{8188eu,8192eu,8812au,8821au,8821cu,8852au,88x2bu}` are
third-party out-of-tree drivers, each pinned to an upstream commit in `drivers/SOURCES.md`,
built only for the transitional Linux tier (frozen by ADR 0047; superseded by heqk and the
in-kernel `rtw88/89`). Forking vendor code to quiet a scanner would be the wrong fix.
- **14 × `cpp/command-line-injection` (critical)** — all in `rtl8812au/tools/WiFi_Direct_User_Interface/p2p_api_test_linux.c`,
  a Realtek demo utility. Never built or shipped: the image build runs only `make -C $KDIR M=… modules`.
- **10 × `cpp/static-buffer-overflow` (critical)** — `rtl8852au/…/halbb_cmn_rpt.c` writes `rssi_tmp[1]`
  with `rssi_tmp[HALBB_MAX_PATH]`. RTL8852A is `BB_IC_AX_2SS` → `HALBB_COMPILE_ABOVE_2SS` →
  `HALBB_MAX_PATH = 2`: in bounds. CodeQL analysed a configuration without the chip define.
- **118 others** (`comparison-with-wider-type`, `overflowing-snprintf`, WEP/TKIP "weak crypto"
  required by the 802.11 protocol, …) — upstream code quality; report upstream if pursued.

## V1 (`legacy/v1/`)
Fixed in this change set; per-alert outcome in `code-scanning-triage-2026-11-08-v1.json`.

## GitHub state vs this record
At 05:53–05:54 on 2026-11-08 all 328 alerts were bulk-dismissed in the GitHub UI as "used in tests".
That label is accurate for only a minority; **this file and the `-v1.json` are the authoritative
per-alert record**. In particular the 44 V1 alerts marked `fixed` were real vulnerabilities and are
fixed in code by this change set (dismissal does not remove a bug). Two `needs_human` items remain:
#975/#976 — third-party CDN scripts in `fortress/web/templates/base.html` load without SRI
(`integrity=`); add hashes or vendor the files locally.

## How to re-check
`gh api "repos/hookprobe/hookprobe/code-scanning/alerts?state=open&per_page=100" --paginate`
— after merge, CodeQL re-runs on `main` and closes every alert whose code was fixed.
