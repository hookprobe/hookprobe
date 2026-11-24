<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Asynchronous OS-image verify / install (pre-soak finding 7)

**Problem.** `POST /api/upload/finish` and `POST /api/upload/activate` for an `os_image` did their work inside the
HTTP request, so inside the AP loop: about 5 s to verify (stream-hash the staged image, check the hybrid signature,
hash the boot-loader prefix of both images and the running slot) and about 5 s to install (copy into the inactive slot
and re-hash it). Wi-Fi and forwarding stopped for that long (`[WDOG] worst_loop_gap_ms` 4,923 → 9,988).

**Change.** The same checks and the same copy, resumable (`otaimg::CheckJob`, `otaimg::InstallJob`). The AP loop
calls `upload::step()` every pass and each call does at most one bounded step: 64 KiB hashed or 64 KiB copied. Order,
refusals and refusal texts are those of the synchronous `check` / `install` (`[P15-otaimg-async]` proves the plan and
the refusals are identical).

## Contract (opt-in, backward compatible)

The synchronous behaviour is unchanged unless the client asks for `async=1`. The management ABI path (`CFG_STAGE`)
stays synchronous.

| Call | Body adds | Reply |
|---|---|---|
| `POST /api/upload/finish` (os_image) | `async=1` | `{"ok":true,"pending":"verifying","poll":"/api/upload/job"}` |
| `POST /api/upload/activate` (os_image) | `async=1` | `{"ok":true,"pending":"installing","generation":N,"poll":"/api/upload/job"}` |
| `GET /api/upload/job` | — | `{"kind":"verify"\|"install"\|"","state":"running"\|"done"\|"failed","done":B,"total":T,"error":"…","generation":N,"length":L,"digest":"<hex>","journal_seq":Q\|null}` |

- **Verify:** poll until `kind == "verify"` and `state` is `done` or `failed`. On `done`, `generation`, `length` and
  `digest` are what the synchronous finish returns. The activate envelope (R6 = D) binds them exactly as before. On
  `failed`, `error` is the synchronous refusal text and the upload has ended.
- **Install:** poll until `kind == "install"` and the state is final. On `done` the device reboots into the trial slot
  about 2 s later (as after a synchronous activate) and `journal_seq` is the audit record. On `failed`, the running
  slot is untouched.
- `done` / `total` are bytes (verify) or sectors (install) of the current stage, for a progress bar. Verify has
  several stages, so the bar restarts per stage.
- Data packs (`shield_*`, `ioc`, `rules`, `wan`, `wifi`, `policy`, `config`) ignore `async`.

**Mission Control (designer-owned):** `store/packUpload.ts` still uses the synchronous form, which works unchanged.
Adopting `async=1` for `os_image` is what removes the Wi-Fi stall for updates made from the UI. `os/kernel/tools/hq-upload.py`
uses it already.
