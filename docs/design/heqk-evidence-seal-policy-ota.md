# Finding 2026-11-13: the sealed evidence log is lost on every OTA update and rollback

**Status:** open — needs an operator decision (it changes which measurements the evidence keys are bound to).
No code changed.

## What happens

`prodfull::ProdFull::init` seals the AP image's evidence log (`evlog`, DataVolume) and the M3 snapshot under
`boot_abi::SEAL_POLICY_STRICT` = PCR0 (HBoot self-measurement over the OTP CRTM anchor) | PCR1 (kernel payload) |
PCR2 (boot config) | device id | SVN floor. `seal::Policy::digest` hashes every selected PCR, and the key is
`HKDF(SRK, salt = policy digest)`. So the evidence key exists only for that exact HBoot + kernel + boot config.

Metal evidence (serial, MB16 OTA batch, main `fc244e45`):

| Boot | `[AP-EVLOG]` at boot | Then |
|---|---|---|
| m16b TRIAL (new kernel) | 0 records kept | — |
| m16b cold (committed) | 0 records kept | — |
| m16c TRIAL (rollback test) | 0 records kept | 1 detection sealed |
| m16b cold (rolled back) | **0 records kept** | 1 detection sealed |

Same build, ordinary power cycles keep the log (MB22: 3 → 3 → 3, then 10 kept). The owner journal (`ownerapi::install`,
keyed by the SRK only) and the sealed configuration (`artstore::set_cfg_seal`, SRK + device id) **do** survive OTA
(MB16: journal 3 → 3 → 5 records).

So today every signed update, and every automatic rollback, silently starts the evidence history from zero: the
detections a customer saw before an update are gone from Mission Control and from the sealed log.

## Options (operator decision)

| | Binding for evidence log + snapshot | Survives kernel OTA / rollback | Survives an HBoot change | Survives an SVN floor raise | What the PCR binding still buys |
|---|---|---|---|---|---|
| A | keep STRICT (PCR0+1+2) | no | no | no | a different signed image cannot read the log |
| B | BASE (PCR0 + device + floor) | yes | no | no | foreign HBoot cannot read it |
| C | SRK + device id (as the owner journal / sealed config) | yes | yes | yes | — (SRK is OTP-derived, EL1 cannot re-read OTP since SEC-2; only signed images run) |

**Recommendation: C**, each record keeping the build id / PCR1 it was written under (for forensics). Reasons: secure
boot already refuses any image not signed by the vendor keys, and the SVN floor refuses a rolled-back image before
it runs. The PCR binding then only separates signed builds from each other, and that is exactly what destroys the
history on update. The owner journal and sealed config already made this choice. B is the middle ground if the
operator wants foreign-HBoot separation; it still loses history on an SVN raise.

Migration: switching binding makes the logs sealed under STRICT unreadable once, which is what every update
does today anyway. Pre-release, no customer data exists.

Related (not changed here): `[PROD-FULL] M3: no prior snapshot (fresh disk)` at every boot in MB16, including
same-build cold boots: the 64-event snapshot is not restored on metal (known since 2026-11-05; the evidence log
replaced it for Mission Control restore).
