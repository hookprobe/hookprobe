# REL-08: CYW43455 firmware trap at ~10 h in WPA3 AP mode (2026-11-11)

> **2026-11-12:** the release gate splits REL-08 in two (`tools/release-gate/items.txt`): **REL-08b** is this defect
> (PMKID-cache use-after-free, the RAM correction `wifi-pmkid-fix`); **REL-08a** is the separate, older Wi-Fi TX-stall
> root cause. "REL-08" below means REL-08b; "the REL-08 regression matrix" keeps its name.

## What happened

The REL-05 72 h soak on image W22 failed at hour 10.2.
- The Wi-Fi firmware halted: the mailbox reported FWHALT `0x00040012`, and forwarding over Wi-Fi stopped.
- The host stall detector armed only when deliveries were queued, so it noticed about 20 minutes later.
- The 120 s self-heal reset then recovered the unit, which fails the soak.

The firmware's own trap dump was on the serial log (periodic `[FWCON]` / `[FWTRAP]`):

```
FWID 01-b677b91b
TRAP 4(25fee8): pc 1c827a, lr 19a30d, sp 25ff40, cpsr a000019f, spsr a00001bf
  dfsr 80d, dfar 19
  r0 0, r1 2457f8, r2 99be41f2, r3 99be41f0, r4 1, r5 247900, r6 41be50f1
```

The firmware is `Version: 7.45.265 (28bca26 CY) CRC: 68bafb8c Date: Tue 2023-08-29`, file sha256 `d608f866…a36c3`.

## Root cause (from the shipped binary, load address 0x198000)

1. **The faulting instruction:** `0x1c827a` is `str r3, [r4, #0x18]` with r4 = 1, which writes to `0x19` (= DFAR). It sits
   in the 10-second walk over a firmware list (head at `obj+0x438`, next at `node+0x1c`, countdown at
   `node+0x18`; −1 is not allowed, the walk loops forever on it).
2. **The broken expiry:** when a countdown reaches 0, the walk relinks the list **only if the node is the head**
   (`cmp r4, r3; it eq; streq r6, [r5, #0x438]`), then frees the node (`bl 0x1c811c`). A non-head node that expires
   leaves its predecessor pointing at freed memory, and the next walk uses it. That is a use-after-free.
3. **The insert:** the insert (`0x1c8d20`) caps the list at 16 entries, removing the head correctly (`0x1c813e` relinks).
   It appends new entries at the tail, or refreshes an existing entry in place. Every insert and refresh sets the
   countdown to `0xe10` (3600) at `0x1c8e26`. The walk timer is `0x2710` ms, so the lifetime is 3600 × 10 s = **10 h**.
4. **The caller:** the only insert caller (`0x1b1a90`) is the `auth_status` handler with `flags == 4`
   (`WL_EXTAUTH_SUCCESS`), keyed by the peer MAC (offset 2), with the PMKID at offset `0x2c`. That is exactly what our host
   SAE sends after every WPA3 join. So this is the AP-side **PMKID cache**.
5. **The trigger:** two SAE stations join (A then B), then A re-joins. A's entry is refreshed in place at the head
   while B's older entry sits behind it. B expires first as a non-head node, giving the use-after-free and a trap at
   about 10 h after B's join.

**Upstream:** [raspberrypi/linux #7528](https://github.com/raspberrypi/linux/issues/7528) reports the same trap.
- **Same signature:** trap 0x4, lr `0x0019a30d`, crashes at about 10 h in WPA3/SAE AP mode, also on 7.45.265 and 7.45.286.
- **Same diagnosis:** the PMKID cache relinks only the head on expiry.
- **Status:** Infineon has merged a fix for a coming firmware release. No official firmware has shipped (as of
  2026-11-11).

**Why "other CM5 users" do not see it:** it needs AP mode, WPA3-SAE and at least two SAE stations with a re-join. Linux
users who run exactly that crash the same way (#7528). A Wi-Fi client or a WPA2 access point never creates these
entries. Our default became WPA3 transition on 2026-11-10; the soak was the first run past 10 h with it.

## Fix options and the operator decision (2026-11-11)

| Option | State |
|---|---|
| Licensor (Infineon) firmware with the fix | Merged upstream, not released. **Preferred** once it ships, with exact provenance (CMP-02). |
| In-RAM 4-byte patch: `mov.w r3,#0xe10` → `mov.w r3,#0x7f000000` at `0x1c8e26` (entries never expire; they leave only through the correct 16-entry cap). Feature `wifi-pmkid-noexpire`, OFF by default; exact version string + original bytes guard; read-back verified; boot log line `[WPA3] PMKID-cache expiry …`. The shipped file stays byte-exact. | **Production NO-GO pending written legal clearance** (licence: "without modification"). Dev-bench experiments authorised by the user. |
| Host-side mitigation (re-issue `auth_status` to keep the list sorted) | Incomplete: an entry of a station that has left can no longer be refreshed. Not pursued. |
| FWHALT fast path: act on the mailbox halt within one loop pass, record the trap registers in the sealed crash record, guarded self-heal reset | Built (branch `fix/wifi-fwhalt`). The fallback in every configuration. |
| Soak rule: a firmware-trap self-heal is a recorded event, if traffic is back within 180 s and there are ≤ 3 in 72 h | Operator-approved 2026-11-11. Harness in `tools/diagnostics/cm5-soak.sh`. |

Also from the operator:
- No silent WPA3 downgrade to pass the soak.
- The soak qualifies only firmware we may legally ship. Otherwise: the licensor fix, or a documented MVP limitation for
  WPA3 AP mode.

**Question for counsel / Raspberry Pi / Broadcom (written answer required):** does a temporary runtime modification of the
unmodified firmware image, applied only in volatile RAM on a licensed Raspberry Pi device, constitute a prohibited
modification under the applicable firmware licence, where the original binary remains unchanged and no modified firmware
is redistributed?

## The HookProbe correction (feature `wifi-pmkid-fix`)

The expiry walk at `0x1c823c` is replaced, in chip RAM after the download, by a corrected walk of exactly the same
120 bytes (`0x1c823c`–`0x1c82b4`). Source: `tools/firmware/rel08/pmkid_walk.s`, assembled and linked at that address.
- **Unlink before free:** an expiring head sets `head = next`. An expiring middle or tail entry sets `prev->next = next`,
  the store the vendor code lacks. The predecessor is kept in `r7`; a survivor becomes `prev`. Consecutive expiries
  keep `prev`, so they unlink correctly.
- **The tail is kept:** an empty list frees the timer and clears timer and count; otherwise the 10-s timer is re-armed.
  That is unlike the community patch.
- **The −1 sentinel** keeps the original fatal `b .`.
- **No other code is affected:** the only reference into the range is the timer-callback pointer to the function
  entry (`0x1c8e84` → `0x1c823d`, unchanged). No branch from outside lands inside it.
- **Guards:** the exact original 120 bytes and the version string must match; the write is read back; the boot log
  line `[WPA3] PMKID-cache expiry … expiry walk CORRECTED`. The firmware file stays byte-exact.
- **CI:** `tools/firmware/rel08/check.sh` re-assembles the source and requires it to equal `WALK_FIXED` in `cyw43.rs`.
  With the staged firmware present, it also requires the original bytes and the version. A firmware upgrade therefore
  fails the check instead of mis-patching.

Licensing: the operator opened Infineon case **IFX-261111-2369681** (2026-11-11). It requests the corrected firmware
and written licensing clarification. The operator has taken the legal question over.

## The community "linked-list correction" (bnicolae, raspberrypi/linux #7528)

The fix is published only as a patched binary (`rpi-firmware-nonfree@5e5d95e`, `cyfmac43455-sdio-wpa3.bin`, sha256
`e755da6a…`). It is based on **7.45.286** (`be70ab3 CY`, CRC `8b7601a5`), not on our 7.45.265. Diffed against the
unmodified 7.45.286 from `Infineon/ifx-linux-firmware`, it changes 63 bytes in one function (`0x1c9308`–`0x1c9354`,
the same walk as our `0x1c823c`):
- **What it fixes:** it tracks the predecessor in `r5` and unlinks a middle node correctly (`str r6, [r5, #0x1c]`,
  or the head).
- **What it drops:** to fit, it also removes the function's tail, which stopped the timer when the list was empty and
  otherwise re-armed the 10-s expiry timer. The patched walk returns (`pop {r4-r7, pc}`) and never re-arms. The old
  tail is unreachable behind `nop`s.
- **Net effect:** the walk runs once (~10 s after the first insert) and entries never expire after that. That is the
  same outcome as our 4-byte lifetime patch, reached by rewriting the function instead of changing one constant. It
  is not a complete correction (that needs a correct unlink AND a periodic timer). It does not apply to 7.45.265 as-is.
- **Our file:** it is byte-identical to Raspberry Pi's `cyfmac43455-sdio-standard.bin` (git blob `fd7a32de…`, trixie
  and bookworm trees), so every Raspberry Pi OS user running a WPA3 AP has this defect.

Infineon's trial build (`cyfmac43455-sdio_pmkid_expire_fix_testonly.bin`, sha256 `92f91d59…` per the operator) is the
only candidate for a real fix. It carries unrelated changes (an SAE timeout). Test it independently on the bench;
**do not ship it.**

## Experiments (dev CM5 only; test images deleted after)

Result (2026-11-11, dev CM5, test-only images):
- **A, trigger:** lifetime 120 s, no fix. Two SAE joins then a re-join gave a **firmware trap ~2 min later**: type
  0x4, pc `0x19a330`, lr `0x19a30d`, the exact #7528 signature. The new FWHALT fast path reset the unit about 1 min
  after the trap (W22: ~22 min).
- **A, control:** same, no re-join. **No trap** in 6 min, traffic OK.
- **B:** original firmware plus the RAM lifetime patch, same trigger. **No trap.** Both radios kept traffic (92 Mbps).
- **Stopped:** an 11 h original-timing run on B, superseded by the correction.
- **C, the correction** (`wifi-pmkid-fix` + the 120-s test firmware): the exact trigger that trapped in A in ~2 min,
  then 12 alternating re-joins (expiries at head / middle / tail and consecutive). Then 300 s quiet: every entry
  expired, the list emptied and the timer was freed. Then re-joins re-created the timer. **No firmware halt in
  1,670 s, 17 SAE keyings, traffic OK.** Boot log: `expiry walk CORRECTED in chip RAM`.
- **Next:** a 72 h soak on the original firmware with the correction (every `wpa3` build now carries it), with two
  SAE stations associated.

### Required regression matrix before any firmware fix is accepted (operator 2026-11-11)

Run against the exact firmware we may legally ship:
- repeated WPA3-SAE join and leave;
- several clients expiring at different list positions;
- re-join before and after expiry;
- consecutive expiries;
- WPA3-only and WPA3 transition;
- WPA2 regression;
- STA roaming between WPA3 APs;
- allocator / memory integrity where instrumentation permits;
- a 72 h sustained WPA3 AP test.

- **A:** a test-only firmware copy with the lifetime set to 12 ticks (120 s). Trigger (A join, B join, A re-join) and
  control (no re-join).
- **B:** the original firmware plus the RAM patch, same trigger.
- **Results:** `docs/design/metal-evidence/` (below, once run).

## Operator decision 2026-11-11 (1A)

The correction ships **on by default with `wpa3`**. Caveat from the operator: it needs **ongoing compatibility testing
and vendor coordination** (Infineon case IFX-261111-2369681). Concretely:
- every firmware upgrade re-runs `tools/firmware/rel08/check.sh` (the patch refuses to apply to any other image);
- the REL-08 regression matrix (above) runs on every candidate release;
- the correction is removed once a licensed Infineon release carries the fix.
