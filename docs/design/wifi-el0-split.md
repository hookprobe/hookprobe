# Wi-Fi fault isolation: separate EL0 bus server and WPA security server (ADR 0065 step 4g)

**Status:** design for the operator decision of 2026-11-15 ("approve fault isolation with a mandatory separation
between the Wi-Fi bus driver and the WPA security control plane"). Nothing below is built yet. ADR 0065 is not
changed by this document. The amendment text in §10 goes to the operator as a separate `docs/adr` PR.

## 1. The rule being implemented

- **Bus server (`el0-wifi`).** It runs the SDIO/SDHCI bus, SDPCM and firmware I/O, and is restartable on its own.
- **Security server (`el0-wpa`, new).** A separate, stateful EL0 server that holds the WPA 4-way authenticator, the
  SAE engine and the PMKSA cache.
- **Bus faults never reach the security server.** A bus-server timeout, stuck read or crash never resets it and
  never erases its PMKSA cache.
- **The kernel is a broker only.** It moves bounded, validated frame and event records between the servers. It never
  receives or retains Wi-Fi key material.
- **Per-station containment.** A fault during one station's handshake may make that station retry. It must not
  affect other stations or the PMKSA cache.

## 2. Where key material is today (and what has to move)

| Secret | Today | After the split |
|---|---|---|
| SAE secrets, SAE PMK | el0-wifi (step 3c) | el0-wpa |
| PMKSA cache, 4-way state (ANonce, PTK, KCK/KEK) | el0-wifi | el0-wpa |
| WPA2-PSK PMK (`psk`) | **kernel**: derived from the passphrase, passed in every `Start` | el0-wpa derives and keeps it |
| GTK (`AP_GTK`), IGTK (`w3().igtk`) | **kernel**: generated at AP start, installed by the kernel, copied into each M3 | el0-wpa generates and keeps them |
| Pairwise TK | **kernel**, transiently: `Out::Keyed { tk }`, then the kernel's `wlc_set_key` | never leaves el0-wpa except into the key-transfer page (§4) |
| AP passphrase | **kernel**, from the sealed config | see decision **D-a** (§9) |
| In-kernel keyer fallback (ADR 0065 D5) | kernel copy of the authenticator, used when el0-wifi is down | **removed** (it holds keys by construction). See D-b. |

The bus server sees a key only inside one key-install call (§4), on its way to the chip.

## 3. IPC design

The model is the existing synchronous excursion: one EL0 call at a time from the AP loop, a bounded budget, no
scheduler. Each server has its own address window, control page and supervision record (`el0srv::Server`). The
kernel calls one server, checks the reply, and calls the other.

- **Frames.** Bus server → kernel: RX records (`rxmsg`, the kernel re-derives the SDPCM header). Kernel → bus server:
  TX/control requests (`txmsg`, `ctlmsg`). These already exist; the hot path does not change.
- **Management to the security server.** The kernel classifies frames:
  - EAPOL-Key and SAE auth frames go to el0-wpa through the existing `keymsg` / `saemsg` records;
  - association RSNE facts go through the existing `rsnassoc` record.

  el0-wpa answers with frames to send (M1/M3, SAE commit/confirm). Those carry no plaintext key: the M3 key data is
  KEK-wrapped. The kernel hands them to the bus server's TX path.
- **Key install (new; the only path a key takes to the chip).**
  1. el0-wpa writes one key record (station MAC, key index, cipher, key bytes) into the **key-transfer page** and
     returns only an install handle: station, index and a sequence number.
  2. The kernel calls the bus server's `CMD_KEY_INSTALL(handle)`. The bus server reads the record, builds the
     `WLC_SET_KEY` / `wsec_key` request, writes it, wipes its stack buffer and the record, and returns ok/fail.
  3. The kernel zeroes the page afterwards. It writes zeros and never reads the page.
  4. el0-wpa learns the result through the next call (`CMD_KEY_RESULT`).
- **Key-transfer page mappings.** One 4 KiB page: RW in el0-wpa, RO in el0-wifi, mapped in no other server. It
  never appears in the crash record, the management ABI or a log.
- **Authorize / deauthorize** (`WLC_SCB_AUTHORIZE`, deauth) are ordinary control requests the kernel asks the bus
  server to send. They carry no key.
- **Validation.**
  - Every reply is decoded by a pure, fuzzed `hal` decoder with fixed bounds.
  - A malformed reply counts as a fault of the server that sent it.
  - Install handles are checked against the station the kernel is keying, so el0-wpa cannot make the bus server
    install a key for a station the kernel did not ask about.

## 4. Supervision and restart model

The two servers are supervised independently: separate `Server` records, budgets, backoff and counters. A fault in
one never touches the other's pages.

**Bus server (`el0-wifi`): stateless across a restart.**
- **Fault** (exception, budget overrun, malformed reply, or `CMD53` stuck past its bound):
  - reset only el0-wifi: restore its image pages and zero its control page and rings;
  - terminate the in-flight bus operation in the device: `rxfail` for a read, `txfail` for a write;
  - if a key install was in flight, zero the key-transfer page and report the install as failed to el0-wpa. That
    station's handshake fails and it retries.
- **Backoff:** 50 ms, doubling to 5 s, as today.
- **While el0-wifi is down:** data frames use the in-kernel bus path (it carries no keys). Key installs wait for
  the server; the handshake retransmit timer keeps the station's 4-way alive.
- **Escalation:** 3 bus faults within 60 s hand over to wifiheal (firmware reload, then the operator's "1 reboot,
  then degrade" rule).

**Security server (`el0-wpa`): stateful, transactional.**
- **Persistent state pages.** Its state (PMKSA cache, per-station handshake slots, SAE slots, GTK/IGTK, PSK PMK)
  lives in pages that a normal restart does NOT restore. The image and stack pages are restored as today.
- **Commit protocol.** Each mutating call works on a shadow copy of the state and commits it by flipping one
  generation word as the last store. A fault mid-call leaves the previous committed state intact.
- **State checksum.** The committed state carries a magic word, a version and a keyed checksum (the key is a random
  value stored inside the state). On restart the server validates it.
- **Per-station containment.** A fault during a call about station S restarts el0-wpa with the committed state, then
  `CMD_FORGET(S)` drops S's in-progress handshake. S retries; every other station's slots and the PMKSA cache are
  untouched. A second consecutive fault on S also drops S's PMKSA entry (poisoned) and S re-runs SAE.
- **Full wipe.** Triggered by a fault outside a station call, a failed checksum on restart, or 3 consecutive faults:
  - the kernel zeroes all el0-wpa state pages and the key-transfer page;
  - the server starts empty: new GTK/IGTK, PSK PMK re-derived;
  - the kernel tells the bus server to deauthenticate every station and install the new group keys;
  - stations re-authenticate in full, so safe re-authentication is forced.

## 5. Timeout strategy

| Where | Bound | On overrun |
|---|---|---|
| Bus server call | 20 ms excursion budget (CM5). Read dry budget ≤ 5 ms per call; longer waits are split into ≤ 5 ms calls (4d). SDHCI command spin bounds inside `hal::sdio::Bus` with soft reset. | Timeout = bus fault (§4). |
| Security server call | 50 ms (SAE commit/confirm measured at ~4.6 ms total on CM5; 4-way messages are sub-ms) | Timeout = security fault, per-station containment. |
| Handshake protocol timers | Owned by el0-wpa (`CMD_KEY_TICK`): 1 s resend, 3 sends | Station gets `Failed` and retries. |
| Key install | 1 bus call per key; retried 3× like today | Install failed: that station's handshake fails. |
| Escalation | 3 bus faults / 60 s → wifiheal; 3 security faults in a row → full wipe | |

## 6. Key-isolation analysis

**What the separation guarantees:**
- a bus-server compromise or bug cannot read the PMKSA cache, the SAE secrets or the 4-way state (separate address
  space);
- the bus server can see only the key it is installing, inside one call;
- no kernel code path copies, logs, exports or retains Wi-Fi keys:
  - keys never cross the kernel's IPC buffers;
  - the kernel only zeroes the key-transfer page and state pages;
  - the crash record and the management ABI exclude them.

**What it does not claim:**
- **EL1 can read all memory.** The kernel is trusted not to read the pages, by construction and by test (§8 check
  K1). This protects against bug-class leaks (logs, crash dumps, stale buffers) and a compromised bus server, not
  against a compromised kernel. Defending against EL1 would need EL2 stage-2 isolation of the el0-wpa pages, which
  is possible later with the SEC-2 carve-out machinery.
- **Entropy:** the kernel supplies TRNG bytes to seed el0-wpa's DRBG (see D-c).
- **The passphrase:** see D-a.

## 7. Performance impact

- **Hot path (RX/TX, ~10–12 k frames/s):** unchanged. Only the bus server is involved, as in 4b-2b/4c (metal:
  98.5–102.9 Mbps).
- **Per join:**
  - security-server calls as today (a handful per handshake, SAE ~4.6 ms);
  - plus 1–3 bus calls for key installs (~2 µs each, ~1.2 µs measured per excursion);
  - plus one state shadow copy per mutating call (state ≈ 8–16 KiB, a few µs).

  None of this is on the forwarding path.
- **Memory / image.**
  - New window for el0-wpa at `0x1_403A_0000`: image 128 KiB + stack 64 KiB + control 4 KiB + state 32 KiB. The
    key-transfer page goes at the bus window's end. All of it fits below the CM5 user window end `0x1_4040_0000`.
  - The bus server shrinks (no SAE crate). The combined images grow by an estimated ~10–20 KiB of duplicated `hal`
    code, against ~226 KiB of headroom.
- **Loop gap:** no new blocking path. Faults are bounded by the budgets in §5.

## 8. Increments and their tests

Each increment passes, before push: the clippy ratchet, `cargo check` (QEMU + both CM5 sets), `validate.sh` (run
alone), `mc-e2e`, and from S2 on CM5 metal. **Nothing is marked complete on QEMU evidence alone.**

| Increment | What | QEMU evidence | CM5 evidence |
|---|---|---|---|
| S1 | Two-server substrate: second window, independent supervision, persistent state pages that survive a restart, key-transfer page mapping. | `[P-el0srv-split]`: a fault in one server leaves the other's counters, state pages and served count unchanged; state pages survive a restart; a full wipe zeroes them. | — |
| S2 | `el0-wpa` crate: keyer + SAE + PMKSA move out of el0-wifi, with the commit protocol and per-station containment. el0-wifi keeps only the bus. | 4-way + SAE + PMKSA through el0-wpa; a fault mid-call keeps committed state; a fault on station B keeps station A's slot and PMKSA; 3 faults → full wipe. | throughput ≥ baseline; WPA3 join; `cm5-wpa3-check` 7/7 |
| S3 | Key custody: el0-wpa generates GTK/IGTK and derives the PSK PMK; `Keyed` returns a handle; key-transfer page + bus `CMD_KEY_INSTALL`; kernel key statics and the in-kernel keyer fallback removed. | K1: after a full join with known test keys, scan kernel `.data`/`.bss`/stack/IO buffers for the key bytes = none found; key-transfer page zero after each install. | throughput, joins, `cm5-wpa3-check` |
| S4 | Fault injection (bench feature `wifi-inject`, refused by `release_check`) + the operator's evidence batch. | — | the seven required items (below) |

The operator's required evidence, all on CM5 in S4. The Pi provides two stations: onboard `wlan0` and USB `wlan1`.

1. **An injected CMD53 timeout does not reset the WPA server.** The bus server stalls inside a CMD53 once.
   Required: `[WIFI-SPLIT] bus restarts=1 wpa restarts=0`.
2. **A bus-server fault preserves PMKSA entries.** Required: `pmksa_entries` before == after.
3. **A client reconnects using its cached PMKSA after bus recovery.** The Pi reconnects after (1). Required: the AP
   logs `pmkids=1` and a PMKSA-cached association, with no SAE exchange.
4. **A fault in one station's handshake leaves the other station's state.** el0-wpa faults on station B's M2.
   Required: B retries and keys; A's PMKSA entry is intact and A's reconnect is cached.
5. **A WPA-server fault wipes secrets and forces safe re-authentication.** Inject a non-station fault. Required:
   state pages zeroed, new GTK installed, both stations deauthenticated, both re-join with full SAE (`pmkids=0`).
6. **Throughput stays above the ADR 0065 baseline.** Required: `cm5-throughput-check` median ≥ 96 Mbps.
7. **Loop-gap and reconnect-soak gates stay green.** Required: `[WDOG] worst_loop_gap_ms` < 2000 throughout; a WPA3
   reconnect soak (≥ 50 cycles over both stations) all keyed and authorized.

## 9. Decisions needed from the operator (none block S1/S2)

- **D-a — the passphrase.** The AP passphrase is configuration from the sealed config, which the kernel unseals
  (the sealing keys stay in EL1, decision 2026-11-11).
  - *Recommended:* the kernel hands the passphrase to el0-wpa once per (re)provisioning and wipes its copy at once.
    The kernel never holds derived keys. The alternative needs EL0 config unsealing, which conflicts with the EL1
    key rule.
- **D-b — removing the in-kernel keying fallback.** Required by "the kernel never receives key material".
  Consequence: while el0-wpa is down (backoff), new stations cannot key. Existing stations keep working, because
  their keys are in the chip. This fails closed.
- **D-c — entropy.** *Recommended:* the kernel passes TRNG bytes to el0-wpa's DRBG at load and on each re-seed.
  *Later:* grant the RNG page to el0-wpa directly.
- **D-d — `validate.sh` QEMU timeout.** `P15otaimg` sits near 300 s and times out when the host is busy (it passes
  alone, or at 900 s). The gate script is the operator's; the suggestion is 600 s.

## 10. Proposed ADR 0065 amendment (for a separate operator-merged PR)

> D6 (2026-11-15): the Wi-Fi driver is TWO resident EL0 servers. `el0-wifi` (bus: SDHCI/SDIO, SDPCM, firmware I/O)
> is stateless across a restart and may be restarted at any time. `el0-wpa` (4-way, SAE, PMKSA, GTK/IGTK, PSK PMK)
> keeps transactional state that survives its own restart, and is never reset by a bus fault. Keys reach the chip
> only through a key-transfer page (RW el0-wpa, RO el0-wifi) and the bus server's key-install call. The kernel
> brokers records and never reads, copies or retains key material. The D5 in-kernel keying fallback is removed.
> D3's "that server holds nothing else" now applies to `el0-wpa`.
