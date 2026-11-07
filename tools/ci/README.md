# tools/ci — the HookProbe gate spine and heal loop (ADR 0048)

One deterministic gate ladder, run **identically** on a developer box and in GitHub Actions,
plus an autonomous loop that turns red runs into reruns, draft fix-PRs, or human escalations.
**AI proposes, the gates enforce** (ADR 0011 C9): no model ever decides whether a gate passes.

```
             ┌──────────── deterministic GATE SPINE  (tools/ci/gates.sh) ────────────┐
             │ g0 wiring+hygiene → g1 static/unit → g2 QEMU → g3 MC e2e → g4 supply   │
             │ chain → g4r reproducible → g6 metal (self-hosted CM5)                  │
             └───────────────────────────────────────────────────────────────────────┘
   L1 GATE          L2 HEAL               L3 WATCH            L4 RELEASE        L5 LEARN
  ci.yml          autoheal.yml          nightly.yml          release.yml       gate+heal events
  every PR        on any red run        + dependabot.yml     on v* tag         → Cortex graph
                                         + metal.yml
```

## Run it

```bash
tools/ci/gates.sh --list           # the ladder
tools/ci/gates.sh pr               # g0 g1 g4          (what every PR must pass)
tools/ci/gates.sh full             # g0 g1 g2 g3 g4    (everything QEMU can prove)
tools/ci/gates.sh nightly          # full + g4r        (+ reproducible build)
tools/ci/gates.sh g3               # one gate
```

Results: `out/ci/gate-results.json` + `out/ci/logs/<gate>.log` (+ `out/ci/sbom/`, `repro.json`).
Locally a missing tool is a **skip**; under `CI_STRICT=1` (always in CI) it is a **fail**.

| gate | proves | tools |
|---|---|---|
| g0 | CI is actually wired (W1–W7), CI tooling self-tests, shellcheck | python3 + PyYAML, shellcheck |
| g1 | clippy ratchet (no new findings), validate.sh phase ratchet (no impl phase lost), host unit tests (tlsprov, responder-sim, heqk-sign) | nightly + stable Rust, clippy |
| g2 | heqk boots in QEMU and every implemented phase PASSes (`os/kernel/validate.sh`) | qemu-system-aarch64 |
| g3 | heqk serves Mission Control end to end, incl. the real-browser HTTPS leg (device ECDSA key + X25519MLKEM768) | qemu, mtools, node, Playwright |
| g4 | no known-vulnerable / yanked crate (RustSec via cargo-deny, `deny.toml`), licences + sources policy, npm audit (high+), CycloneDX SBOMs | cargo-deny, npm, syft |
| g4r | the shipped `prod` kernel builds bit-for-bit identically twice (ADR 0036 R1) | nightly Rust |
| g6 | `mc-e2e-metal.sh` on the CM5 bench (self-hosted runner, never from a PR) | bench |

### Ratchets (why the gates are green on day one and only get stricter)
- `baselines/clippy.json` — heqk had 231 clippy findings when the gate landed. A PR may not add one
  (per crate × lint); when it removes some, `clippy_ratchet.py --update` locks the lower floor in.
- `baselines/validate-phases.txt` — the 91 implemented validate.sh phases. Flipping one to `plan`
  or deleting its row is the cheapest way to "fix" a red QEMU gate — the ratchet forbids it.
  New phases: `phase_ratchet.py --update`.

## The heal loop

```bash
tools/ci/heal/heal.py                       # run the PR gates, heal what's red (agent: claude if installed)
tools/ci/heal/heal.py --gates g1 --agent none          # classify + render the agent prompt only
tools/ci/heal/heal.py --results out/ci/gate-results.json   # heal an existing run
tools/ci/heal/heal.py --push                # also push autofix/* + open a DRAFT PR
python3 tools/ci/heal/classify.py out/ci/gate-results.json # just classify
```

1. **classify.py**: deterministic regex rules → `rerun` (infra, QEMU-on-TCG budget) · `autofix`
   (build/test/e2e/QEMU regression, reachable vulnerable dependency, new clippy/shellcheck finding)
   · `human` (leaked secret → rotate, licence/policy, CI wiring, downgraded phase, unknown).
2. **autofix** happens in an isolated `git worktree` on `autofix/<signature>-aN`. The agent gets
   `prompt.md` (evidence, rules, protected paths). It may not commit; the harness does.
3. **autofix_guard.py** rejects the diff if it touches `protected-paths.txt` (gates, workflows,
   deny/baselines, signing + keys, ADRs), removes tests/asserts/PASS markers, adds a suppression
   (`#[ignore]`, `#[allow]`, `|| true`, `continue-on-error`, …), or is too big to review.
4. The originally red gate must re-run **green in that worktree**. Only then is it `proposed`.
5. A human merges. Always. Max 2 attempts per signature; `HEAL_MAX_BUDGET_USD` caps spend.

On GitHub, `autoheal.yml` runs `triage_run.py` on every failed `ci`/`nightly`/`build-heqk`/
`secrets-scan` run: one deduplicated issue per failure signature, a single rerun for transient
failures, and (default branch only, with `secrets.ANTHROPIC_API_KEY`) the same `heal.py` flow
ending in a draft PR. Set `secrets.AUTOFIX_TOKEN` (GitHub App / fine-grained PAT) so the draft
PR's own `ci.yml` runs (PRs opened with `GITHUB_TOKEN` do not trigger workflows).

## Adding things
- **New lockfile / detached workspace** → add it to `lockfiles.txt` **and** `.github/dependabot.yml`
  (G0 W4/W5 fail until you do).
- **New gate** → add `gate_<id>` to `gates.sh`, wire it in a workflow, add its regex to
  `g0_wiring.py` `REQUIRED_WIRING` (W6), add a classifier rule + fixture test.
- **A dependency exception** (`deny.toml` ignore / licence) → a human PR with a reason and a
  re-review trigger. It is a protected path, never an autofix.

## One-time GitHub setup (operator)
1. Branch protection on `main`: require **`ci-ok`**, `heqk QEMU gate`, and the secrets-scan jobs.
2. Secrets: `ANTHROPIC_API_KEY` (enables autofix), optionally `AUTOFIX_TOKEN`.
3. Register the bench host as a self-hosted runner labelled `cm5-bench` with `HEQK_METAL=1`.
