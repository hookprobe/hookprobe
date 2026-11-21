# Plan: remove the Linux tier from the repository

**Progress (2026-11-21):** steps 0 (#1386), 1 (#1398), 3a (#1395) and 3 (#1396) are merged; the last
11 files under `legacy/` go in `agent/remove-legacy-leftovers`. Licences of what ships: #1414 (device tree
and firmware), #1415 (crates and browser code in the image). Next: step 2, then step 4.

_Drafted 2026-11-20 by the agent, after the operator said "no linux, remove anything about linux"
(AB-15). Nothing below has been executed except PR #1386 (the Linux-tier architecture doc).
Facts are from `origin/main` @ `6ab20c2e`._

## 1. Where things stand

- **Nothing ships Linux.** `release.yml` attaches only `heqk8.img` (prod-mc CM5 profile). None of the
  8 workflows in `.github/workflows/` builds a Linux image; the Linux tier's own workflows sit inert in
  `legacy/linux-tier/ci-workflows/`.
- **`legacy/linux-tier/`** is 5,226 files, ~270 MB in the tree: `base bootstrap builder ci-workflows crates
  fleet manifest modules platforms security supervisor`. Last real change 2026-11-07 (Dependabot fixes);
  it still draws dependency alerts.
- **`legacy/v1/`** (1,178 files) is the original Python/Zig HookProbe. It also runs on Linux.
- **The existing teardown plan is stale.** `docs/design/heqk-unbuild.md` (2026-07-30) and BuildPlan's
  C-unbuild table (U1–U6) say "the Linux M1 image keeps shipping on rpi-native" and "marked superseded,
  never deleted until gates prove nothing broke on heqk". The first is no longer true (above). The second
  is a rule the operator now has to waive or keep: see D4.
- **Git history keeps everything.** Deleting from the tree loses nothing; any file can be restored from
  history. A clone stays the same size unless history is rewritten (not proposed: D2).

## 2. Live dependencies: these break if the tree is deleted first

| # | What | Where | Fix before deletion | Owner |
|---|---|---|---|---|
| L1 | **The factory disk image reads the CM5 device tree from the Linux tier.** Default `DTB=$ROOT/legacy/linux-tier/builder/kernel-build/out/bcm2712-rpi-cm5-cm5io.dtb` (sha256 `2ca3879f…d11e`) | `os/build/make-cm5-heqk-disk.sh:173` | Move the `.dtb` (and its `SHA256SUMS` line) to `appliance/cm5/` or `os/drivers/firmware/`, change the default path, record its provenance and licence (compiled from Raspberry Pi kernel device-tree sources). Prove the disk image is byte-identical before/after. | operator / release-engineer (Red-tier script) |
| L2 | `.gitleaks.toml` allowlists the Linux tier's deterministic dev keys (`legacy/linux-tier/builder/release.key`, `.mldsa`) | `.gitleaks.toml:42-54` | Remove the allowlist entries in the same PR as the deletion (the keys go with it). | operator (secret policy) |
| L3 | A Claude workflow that builds the Linux tier | `.claude/workflows/base-tier-build.js` | Delete. | operator (governance) |
| L4 | `CLAUDE.md` says the `legacy/linux-tier/crates/hookprobe-api` contract "is now the interface spec the on-device server implements"; ADRs 0008, 0021, 0025–0030, 0047 cite it | `CLAUDE.md`, `docs/adr/` | Point at the real contract: `os/kernel/kernel/src/http.rs` (server) and `os/mission-control/src/store/*` (client). | operator |
| L5 | The capability token names are cited from `legacy/linux-tier/manifest/schema/manifest.schema.json` | `appliance/hookprobe-sbc/README.md:24` | Cite the heqk capability list (`/api/health` `capabilities`) instead. | agent |
| L7 | **The kernel's device-fingerprint table is generated from V1.** `fpdb.rs` = `gen_fpdb.py legacy/v1/products/fortress/lib/fingerbank.py` (122 KB, literal dicts parsed with `ast`) | `os/build/fpgen/gen_fpdb.py:5` | Move `fingerbank.py` next to its generator (`os/build/fpgen/fingerbank_v1.py`, header kept) before deleting `legacy/v1`; prove the regenerated `fpdb.rs` is byte-identical. | agent |
| L6 | Gate scripts special-case `legacy/` | `tools/ci/g0_wiring.py`, `lockfiles.txt`, `release_check.py`, `deny.toml` | Harmless after deletion. Simplify only if `legacy/v1` also goes (D1). | operator (gate machinery) |

Not dependencies (text only, safe to leave or reword later): kernel provenance comments ("ported from the
Linux-tier napse-capture / dnsxai", `ja4.rs`, `dga.rs`, `validate.sh` PASS descriptions), `.gitignore`
patterns, `tools/intel-data/.../hookprobe_ioc_v1.py` (names the old feed format in a docstring).

## 3. Decisions for the operator

| | Question | Recommendation |
|---|---|---|
| D1 | Remove `legacy/v1/` too? It is Linux software, but it is also the record of what fielded V1 units run. | Yes, in its own PR after `linux-tier`, unless a V1 unit still needs fixes from this repo. |
| D2 | Tree deletion or history rewrite? | Tree deletion only. A rewrite forces every clone and worktree to be rebuilt (as the author rewrite did) for no product gain. |
| D3 | ADRs that only describe Linux (e.g. 0019 bootc, 0029, 0030, 0032; 33 ADRs mention it): delete, or keep with status "Retired: Linux tier removed"? | Keep the files, change the status line. ADR numbers are cited across the repo and the decisions are history. |
| D4 | Waive the "never deleted until gates prove nothing broke on heqk" rule (ADR 0044 D4, heqk-unbuild.md §0)? | Yes for the repository: nothing ships Linux and history keeps the code. Mark the rule satisfied by "no shipping consumer", not by metal gates. |
| D5 | Who edits the 39 `os/kernel/` files that mention Linux? | homepods, or nobody: they are provenance comments, and `validate.sh` PASS lines must not be edited by the agent (guard A6). |

**Operator answer (2026-11-20): all five recommendations accepted.** `legacy/v1` goes too (D1); tree
deletion only, no history rewrite (D2); Linux-only ADRs stay with a "Retired" status line (D3); the
"metal gates first" rule is waived for the repository (D4); kernel provenance comments are left to homepods (D5).

## 4. Order of work (one PR each, all drafts, a human merges)

| Step | PR | Content | Size | Owner |
|---|---|---|---|---|
| 0 | #1386 | Delete `docs/architecture/Readme.md` (done, draft) | 13 files | agent |
| 1 | L1 | Move the CM5 `.dtb` out of `legacy/`, repoint `make-cm5-heqk-disk.sh`, prove identical disk image | 3 files | operator / release-engineer |
| 2 | L5 + MC comments | `appliance/` READMEs; `plannerApi.ts` / `dnsLive.ts` comments; drop `PUBLIC_PLANNER_API_BASE` Linux example | ~5 files | agent |
| 3a | **Delete `legacy/v1/`** (D1), after moving L7 | `git rm -r legacy/v1`, `fingerbank.py` → `os/build/fpgen/` | 1,178 files | agent |
| 3 | **Delete `legacy/linux-tier/`** except `builder/kernel-build/out/` (the CM5 `.dtb`, until step 1 moves it) | `git rm -r legacy/linux-tier`, `.gitleaks.toml` L2, `.gitignore` lines, `.claude/workflows/base-tier-build.js` | 5,226 files, one directory | operator (protected paths in the same PR); agent can prepare the branch |
| 4 | Docs, unprotected | ~42 files: `docs/` (outside `adr/` and `autonomous-agent/`), `README.md`, `CONTRIBUTING.md`, `appliance/`. BuildPlan Track B and C-unbuild become "removed 2026-11-xx"; `heqk-unbuild.md` gets a closing status; dated research and journal rows stay as written | 3 PRs of ≤15 files | agent |
| 5 | Governance | `CLAUDE.md` (decisions #1/#2, the ADR 0047 banner, layout block, L4), `SECURITY.md`, `LICENSING.md`, 11 `.claude/` files, ADR status lines (D3) | ~50 files | operator, or agent with explicit link-and-status-only permission |
| 6 | `legacy/v1/` | only if D1 = yes | 1,178 files | operator |
| 7 | Gate cleanup | L6, only if `legacy/` is gone entirely | 4 files | operator |

Steps 1 and 2 can run in parallel; 3 waits for 1; 4 and 5 wait for 3 (so the docs say "removed", not
"to be removed").

## 5. How each step is proven

- **Step 1:** `make-cm5-heqk-disk.sh` before and after on the same commit → identical `.img` sha256. Needs a
  Linux build host or the bench; not possible on this Mac.
- **Step 3:** CI on the PR: g0 (wiring, lockfiles, release_check), g1, g3, g4 and secrets-scan green;
  `build-heqk.yml` green; `git grep -n "legacy/linux-tier" -- . ':!legacy'` returns only history-marked text.
- **Steps 4–5:** no markdown link to a deleted path (`git grep` for `](…legacy/linux-tier` and
  `architecture/Readme.md`); a fresh macOS checkout is clean.
- **Afterwards:** Dependabot / code-scanning alerts on `legacy/linux-tier/**` close on their own.

## 6. Risks

- **Lost reference for ports still to come.** M3 persistence (SQLite evidence graph), M4 DNS/RPZ and M5 signed
  Wasm modules are ⬜ on heqk and the Linux tier was their working reference. Mitigation: history plus a tag
  on the last commit that contains it (e.g. `linux-tier-final`, an operator Red step).
- **Other sessions.** No open PR touches `legacy/` today (checked 2026-11-20). homepods' boxes
  (fortress001) build from their own checkouts; tell that session before step 3.
- **Licence of the moved `.dtb`.** It is compiled from Raspberry Pi device-tree sources; record the source
  and licence next to it in step 1.
