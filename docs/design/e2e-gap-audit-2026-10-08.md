# End-to-end gap audit + phased close-out plan (2026-10-08)

**Scope:** the whole flow — CM5/heqk datapath, device→operator evidence plane, Linux/UEFI tier
(bootstrap → manifest → supervisor → modules → evidence → API → UI). Four parallel read-only
audits, every high-severity claim re-verified against code before fixing. Goal: close the
backend/kernel/bus/drivers so work can move to the user experience.

**Base:** branch `worktree-heqk-premetal-gaps` @ fc18f43. `master` is 217 commits behind it;
fast-forwarding `master` is an operator (Red) decision.

## Baseline

| Gate | Result |
|---|---|
| heqk `validate.sh` (QEMU) | green: 73/73 implemented phases (the first run's 29 FAILs were host starvation, see S0-2) |
| Linux workspace `cargo test` | 1499 passed / 0 failed |
| CM5 `prod` flavour | not built by any gate before this audit (see S1-1) |

## Stage 1: DONE (QEMU-proven, all CM5 flavours build, validate.sh green)

| # | Defect | Root cause | Fix + regression |
|---|---|---|---|
| S1-1 | **Shipped `prod` image never started the IPS.** `cm5_p10_probe()` ran an AP/NAT `loop{}` that never returned, so `cm5_prod_service()` was unreachable. AP-client↔WAN traffic was NATed with no `packet::verdict`. | A bench switch (`const AP_MODE: bool = true`) with no feature gate. `validate.sh` boots only the QEMU flavour, so the prod flavour was never gated. | `apmode`/`stajoin` features; `prod`+bench mode = `compile_error!`. CI step in `build-heqk.yml` builds `prod`, asserts `prod,apmode` is refused, and greps for credential literals. |
| S1-2 | **Wi-Fi credentials in source.** A real network passphrase (STA join) and the AP PSK were in source, and the AP PSK was printed on the console. | Bench constants. | Build-time env only (`HEQK_AP_PSK`, `HEQK_JOIN_SSID/PSK`); const-asserted when the feature is on. **History purge = operator (Red)**: the literal is still in git history. Rotate that Wi-Fi password. |
| S1-3 | **Resource-shed latched permanently** (ADR 0023 violation): after ~80k ACK segments (one large download), `saturated` stayed true until reboot, and the top talker was shed forever. | `FLOW_COUNT` was a lifetime counter bumped on every ACK, never decremented. The code comment promised a real gauge "in M2.3". The A7 self-test only exercised the pure `table_saturated(85_000, …)`, never the live accounting. | A decaying new-flow (SYN) gauge over a 60 s two-bucket horizon. `[P8-flow]` "A7 live gauge" case: 100k ACKs leave it unchanged, it decays, and it self-reverts. |
| S1-4 | **Legit fragment dropped as a signature hit.** | `parse_ipv4` ignored the fragment offset. The IPv6 Fragment(44) arm ignored its offset too. | Non-first fragments report no L4. `[P8-flow]` "LEGIT fragment" case covers v4 and v6. |
| S1-5 | **Signed containment silently lost on hash collision.** A colliding MAC overwrote a slot; the policy still reported all entries applied. | Direct-mapped collision-evict in an authority-only table (C16). | Open addressing with full-key compare. `set_reach` returns whether the entry was placed. An unplaceable policy is rejected and the table reset (`TableFull`, fail-open). Collision case added to `reach_selftest`. |
| S1-6 | **Anti-rollback floor could drop a generation.** | The reserved window LBA 2016–2047 is shared by 4 users with ad-hoc LBAs. The reach-log fallback [2034,2046) overlapped the per-boot cookie (2040) and OTA state (2044). | No fallback: without a DataVolume, the floor is unavailable and the plane stays disarmed (C12). |
| S1-7 | **Incident severity mixed two scales.** A *suspicious* DNS lookup rendered CRITICAL, incident priority came from the least-severe detection, and confidence could show 167%. | dns_dga, aegis_reflex and aegis_guard wrote higher-is-worse values into a column whose canonical scale (napse, host-EDR, UI `severityLabel`) is 1=CRITICAL. | Producers normalized; one-shot `PRAGMA user_version` value migration for deployed DBs; `correlate_incident` uses the worst (min) severity, with score `(6-min)/5`. Tests updated and added. |
| S0-2 | **False-red QEMU gate under load.** | Fixed 45 s budget. The heal report blamed P1 when the real cause was a timeout. | `HEQK_QEMU_TIMEOUT` (default 150 s; passes exit early). The timeout is now named as a timeout, with the host load. |

## Stage 2: evidence plane (device → operator). Next; QEMU/host-testable

The chain breaks at its first hop on CM5: a heqk detection never leaves the device.

1. Drain the SOAR ring in the prod heartbeat. The ring is never drained in `prod`/`prod-full`, overruns climb, and `on_threat` persists zero-filled `rule_id/src/severity`.
2. Export v2 frame: `boots`, `cntfrq`, per-boot seq, verdict class (tri-state lost today), `overruns`. `ts` is raw `cntpct` today.
3. Transport: explicit per-record nonce counter + replay window (one lost UDP datagram currently breaks every later frame); re-handshake on decrypt failure.
4. One combined profile carrying both ControlPlane and ProdFull. No image has both today, and `pf.enroll` is never set.
5. An off-device receiver (std binary linking `securechannel.rs`/`export.rs` like `responder-sim`) → JSONL with `device_fp`/`tenant` → evidence ingest (+ columns). Nothing consumes HQX1 today.
6. Tenant from msg2, kept in one place (three disagreeing tenant constants today).
7. **Security:** the device identity key is seeded from `sha256(board serial)`, and the serial is printed on the console. Derive it from the OTP/SRK path (SEC-2), and pin the public key at enrollment.
8. Snapshot ring honesty: persist an `evicted` count, the true head, and an export cursor (replay after reconnect).

## Stage 3: Linux tier wiring. Host-testable; unblocks the UX

1. Serve `ui/dist` from hookprobe-api on a LAN listener, with `API_BASE=''` and a cookie session (SSE can't send headers). Today an off-box browser silently falls back to mock data.
2. Capability gating from `/api/manifest` (a `useManifest()` store). UI capability names (`firewall`, `vpn`, `segmentation`, …) don't exist in `platforms/*.yaml`; reconcile the vocabularies.
3. `--run-wasm` must verify the manifest, `resolve` the module grant, and take crypto policy from the manifest. The planner runs even where `ai_planner` is denied.
4. Manifest origin: compare the embedded cert with the re-derived `DeviceIdentity` fingerprint (integrity ≠ origin today).
5. DNS attribution: the feed emits `q\tsrc_ip`; add `src_ip` to the dns/aegis detection ids (devices currently collapse into one row). The amd64 feed script still lacks `mawk -W interactive`.
6. Smaller: planner DB write sandbox, ingest-time watermark skew, l2guard/quarantine `HOOKPROBE_EVENTS`, fanotify/dga-lm have no unit, grant/file-name mismatches, `ai_reasoning` not in the UI type.

## Stage 4: metal / operator-gated (never faked in QEMU)

- AP mode as a product: run `packet::verdict` on both NAT legs, give Wi-Fi an Access port role, and then lift the `prod`+`apmode` refusal. NAT hardening comes with it: per-MAC leases + MAC/IP binding (flow hijack), remote-endpoint binding + TRNG ports on inbound, per-client cap, WAN lease renewal, gateway-ARP pinning, non-blocking per-station 4-way.
- Single-port promiscuous hairpin (`NCFGR_CAF` + re-TX out the ingress port): decide out-of-band observe vs a true two-port inline.
- Manifest-driven mgmt floor + port roles (hard-coded 10.200.0.0/24 = the fortress customer LAN today, so every customer host is Allowlisted). Add an IPv6 source key (v6 currently bypasses scan/conn-rate/shed and has no floor).
- STA supplicant: verify the M3 MIC, ANonce and replay counter before M4/PTK install. Constant-time MIC compare.
- Connect-scan detection gap (one ACK holds escalation off), and RFC 1858 tiny-fragment flag evasion.
- Red: git-history purge of the credential, fast-forward `master`, signing ceremonies, flashing.
