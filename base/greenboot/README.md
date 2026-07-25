# base/greenboot/ — the OS boot-health gate (mechanism split by tier, ADR 0019)

Module-level safety (self-test → heal → shed, commit-confirmed) protects a *running*
device. This is the complementary **boot-level** gate: it protects against a bad
**image/module update** by producing a per-boot healthy/unhealthy verdict.

**HONESTY (ADR 0019 D2/D3 — the bootc/Debian substrate split):** this README used to
claim the verdict is *always* auto-reverted via `bootc rollback`. That is only true
on a real bootc-managed deployment. On today's shipping **rpi-native** image (mkosi
+ `make-pi4-image.sh`, ADR 0019 F2) there is **no bootc and no second deployment
slot** — an unhealthy verdict is honestly logged as FAILED, and nothing rolls it
back automatically. Recovery on that tier today is a manual reflash; an actionable
rollback needs the A/B image-sync agent (ADR 0019 D3, Phase 3), not yet shipped.
Do not read the diagram below as universal — see "Which tier are you on" further down.

## How it works — UEFI tier, bootc-managed (ADR 0019 D2, Phase 1+)

```
bootc upgrade  →  reboot into new deployment
      │
      ▼
greenboot-healthcheck.service  runs  /etc/greenboot/check/required.d/*
      │
      ├─ 10-hookprobe-soc.sh → reports (via `bootc status`) whether this deployment
      │      is actually bootc-managed, THEN → hookprobe-supervisor --health-gate
      │      verify manifest sig → verify module sigs → reconcile →
      │      self-test/heal → baseline SOC (napse, qsecbit) running+healthy?
      │
      ├─ exit 0  → boot marked GOOD  → deployment confirmed
      └─ exit ≠0 → (greenboot retries) → boot marked BAD → bootc ROLLBACK to last-good
```

On this tier, a new image that boots but can't bring up the SOC (broken module
update, bad manifest, regression) is **automatically reverted in seconds** — the
immutable rootfs makes rollback cheap, and the data partition + device identity are
untouched.

## How it works — rpi-native tier (today's shipping image; no bootc, no rollback yet)

```
mkosi / make-pi4-image.sh flashes a SINGLE-SLOT image  →  reboot
      │
      ▼
hookprobe-selftest.service runs selftest-boot.sh — the actual invoked health path
today (greenboot itself is not installed/wired on this tier; the check script
above only matters once the bootc-managed Containerfile ships, ADR 0019 Phase 1+)
      │
      ├─ PASS → verdict logged, boot continues normally
      └─ FAIL → verdict logged as FAILED, console/journal says plainly that there
                 is NO rollback slot on this image. Manual reflash from a
                 known-good image is the recovery until the A/B image-sync agent
                 lands (ADR 0019 D3, Phase 3).
```

## Which tier are you on?

Both `10-hookprobe-soc.sh` and `selftest-boot.sh` answer this the same way: `bootc`
binary present **and** `bootc status` succeeds against a real deployment → UEFI
tier, rollback is real. Anything else (no `bootc`, or the binary present but this
isn't a bootc-managed root) → rpi-native/single-slot, rollback is **not**
actionable yet. Never assume the optimistic case.

## Layout (baked into the image)

```
base/greenboot/
└─ check/required.d/10-hookprobe-soc.sh   → /etc/greenboot/check/required.d/
```

Containerfile: `COPY base/greenboot/check/ /etc/greenboot/check/`. Note: as of this
writing `greenboot` itself is **not yet installed via apt** nor is
`greenboot-healthcheck.service` enabled anywhere in this repo — the check script is
staged and correct, but its invoker on the bootc/UEFI tier is still a TODO (tracked
under ADR 0019 Phase 1/2, alongside standing up `bootc` itself). Optional `green.d/`
(on healthy: log/notify) and `red.d/` (on unhealthy: capture diagnostics before
rollback) can be added the same way once greenboot is actually wired.

## Verdict policy

`--health-gate` passes when the manifest verifies **and** the required baseline
modules are running after reconcile+health. Default required set: `napse, qsecbit`
(the two core wasm engines staged on every image of every class — NOT `hydra`,
which is `status: stub` per ADR 0015 D3 and would make every boot unhealthy). Tune
per platform with `--require <id>`.

## Try it (no reboot needed)

```bash
# Healthy boot → exit 0:
hookprobe-supervisor /var/lib/hookprobe/manifest.json --modules <signed> --health-gate; echo $?
# Simulate a broken SOC module → exit 1. The supervisor now prints WHICH recovery
# mechanism actually applies (bootc rollback vs "no rollback slot available yet"),
# rather than asserting a rollback that may not exist on this tier:
hookprobe-supervisor … --health-gate --fail napse; echo $?
```

See `docs/OS-platform-report.md` §A (install-time robustness) + §8.x, `docs/BuildPlan.md`,
`docs/adr/0019-bootc-debian-substrate.md`.
