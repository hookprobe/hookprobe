# heqk gate on macOS — report for HomePods (2026-11-18)

> Run by the HookProbe research session **read-only with respect to `os/kernel`**:
> - an unchanged `os/kernel/validate.sh`;
> - a throwaway git worktree of `main` at `c70bd4d3`, removed afterwards;
> - the pinned toolchain `nightly-2026-07-20` (rustc 1.99.0-nightly 9f36de775), installed isolated in a scratch directory;
> - QEMU 11.1.3 (Homebrew);
> - `flock`/`sfdisk` from util-linux (keg-only, added to `PATH`), `mkfs.vfat` (dosfstools), `mcopy` (mtools), and macOS 27's `/usr/bin/timeout`.
>
> Host: Apple M5 Pro, macOS 27.2.1, run at `nice 10`.

## Result

**`VERDICT: all implemented phases GREEN. Kernel is healthy.`** `validate.sh` exit 0, 3 min 31 s wall time.

| Stage | Result |
|---|---|
| Main kernel build | 43 s; 142 compiler warnings in the `kernel` crate, no errors |
| Main QEMU boot | `[ALL] ... GREEN` in 22 s; 160 of 176 implemented markers in this boot (the other 16 come from the later p15-write / OTA / A/B stages, which also passed) |
| Host harnesses | **[P16] verifier soundness: PASS**; **[P-wifi-crypto]: SKIPPED — see finding 1** |

So **the gate runs on macOS 27 / Apple Silicon** with the five extra tools above.

## Finding 1 — the WiFi/WPA crypto KAT has been silently skipped since `52cb2ac0`

- **What breaks:** `os/kernel/tools/wifi-crypto-kat.rs:13-16` includes `../arch-aarch64/src/aes.rs` and `../arch-aarch64/src/wpa.rs`.
- **Why:** commit `52cb2ac0` (SEC-01 step 5b, "WPA crypto moved to hal") moved both files to `hal/src/`. The harness no longer compiles (`error: couldn't find file tools/../arch-aarch64/src/aes.rs`).
- **Why it went unnoticed:** `validate.sh` reports *any* compile failure of this harness as `skip (rustc host build unavailable)`. The gate stays GREEN while the FIPS-197 / RFC 3394 / PBKDF2 / PTK / MIC known-answer tests never run.

**Verified fix:** point both `#[path]`s at `../hal/src/`. In a scratch copy the harness then compiles and prints `[P-wifi-crypto] PASS` (every vector PASS, including tamper rejection):

```diff
-#[path = "../arch-aarch64/src/aes.rs"]
+#[path = "../hal/src/aes.rs"]
 mod aes;
-#[path = "../arch-aarch64/src/wpa.rs"]
+#[path = "../hal/src/wpa.rs"]
 mod wpa;
```

**Suggested hardening:**
- Distinguish "no host rustc" (`command -v rustc` fails → skip) from "harness does not compile" (→ FAIL), for this harness and `[P16]`.
- Otherwise a moved file silently removes a security test from the gate.

**Worth checking in CI:** the same skip line may appear in `build-heqk.yml` logs.

## Notes (not defects)

- The gate's Linux assumptions are `flock`, `sfdisk` and `/proc/loadavg`. The last is only used in a timeout message. On macOS they need util-linux on `PATH`, and that is all.
- 142 `kernel` warnings on the pinned nightly, for awareness only.
- Nothing in `os/kernel` was modified. The fix above was tested only in a scratch copy and is offered as a patch.
