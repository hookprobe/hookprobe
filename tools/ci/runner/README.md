# tools/ci/runner — the gate ladder on an Apple Silicon Mac

heqk is aarch64, so an ARM host is the natural gate box. On a shared x86 box (the N100) every QEMU boot is
emulated *and* competes with other work: false TCG timeouts, as `validate.sh` documents. This folder sets up an
aarch64 Ubuntu VM on a Mac that (A) replaces the shared box for local gate runs and (B) can serve as the
self-hosted runner for `.github/workflows/arm-gates.yml`.

Measured 2026-11-20 on an M5 Pro, `origin/main`, still TCG (no hardware virtualization yet):

| gate | GitHub-hosted x86 (3 nightlies) | M5 Pro |
|---|---|---|
| g1 | 234–356 s | ~242 s |
| g2 (`validate.sh`, all 184 phases) | 351–547 s | 319 s |

The bigger win needs heqk to boot under hardware virtualization. Today it faults on the heap lock before
the MMU is on (reported to the kernel owner). After that fix, QEMU inside this VM can use KVM through Lima's
nested virtualization.

## Why a VM and not macOS directly

Running the gates natively on macOS hits Linux-only assumptions: bash 3.2 (`gates.sh` needs ≥ 4), BSD `mktemp`
(mc-e2e), keg-only `sfdisk` (validate.sh), and a Python without `cryptography` (mc-e2e). The VM is the same distro
as CI, so nothing needs patching, and with **no host mounts** gate code (build.rs, tests) can't touch the Mac.

## A. Local gate box (instead of the shared N100)

```bash
brew install lima
limactl start --name=hp-gates tools/ci/runner/hp-gates.lima.yaml
limactl shell hp-gates -- git clone https://github.com/hookprobe/hookprobe.git
limactl shell hp-gates -- bash -lc 'cd hookprobe && git fetch && git checkout <branch> && tools/ci/gates.sh g0 g1 g2'
```

Results land in the VM at `~/hookprobe/out/ci/gate-results.json`. One heavy run at a time per VM (the
`validate.sh` lock).

## B. Self-hosted runner for arm-gates.yml (operator)

Use a **second** VM so the runner and local runs never share a QEMU budget:

1. `limactl start --name=hp-runner tools/ci/runner/hp-gates.lima.yaml`. On a 24 GB Mac, run at most one of
   the two VMs at the default 6 CPU / 8 GiB, or pass `--cpus 4 --memory 6` to both.
2. GitHub → hookprobe/hookprobe → Settings → Actions → Runners → **New self-hosted runner** → Linux / ARM64.
   Run the shown download + checksum commands inside `limactl shell hp-runner`, then configure with the
   label `hp-gates`:
   `./config.sh --url https://github.com/hookprobe/hookprobe --token <shown> --name m5-hp-gates --labels hp-gates --unattended`
   then `sudo ./svc.sh install && sudo ./svc.sh start`.
3. Restrict it: repo-level runner (or a runner group limited to this repo) with selected workflow
   `.github/workflows/arm-gates.yml@refs/heads/main`.
4. `gh variable set ARM_GATES_RUNNER --body true`. Until then `arm-gates.yml` is skipped, never queued.

`arm-gates.yml` runs g0 g1 g2 on every push to main and g4r nightly. g3 (Mission Control e2e + real browser)
and g4 (supply chain) stay GitHub-hosted, and the required PR checks don't change. Never PR-triggered
(G0 W2), main only, no secrets: the same model as `metal.yml`.

## Compare after a week

```bash
gh run list --workflow arm-gates.yml --json databaseId,conclusion,createdAt -L 20
gh run list --workflow nightly.yml   --json databaseId,conclusion,createdAt -L 20
```

Per-gate seconds are in each run's `arm-gates` / `nightly-g*` artifact (`gate-results.json`). Compare the run
times and the false-failure rate (validate.sh timeout warnings) against the hosted nightly.
