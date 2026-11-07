# CORE-2 — Per-TCB CSpaces — implementable design

Status: **DESIGNED, not yet implemented.** The keystone that unblocks P11/P12 and
clears CORE-1/XC-5/XC-6. This is an architectural change to the capability system —
land it deliberately, with the validation loop below.

## Why (the concrete blocker)

Today there is exactly ONE capability space: `static mut ROOT: Option<CapSpace>`
(`kernel/src/main.rs`), resolved via `root()`, and every EL0 task's `SYS_CAP_IDENTIFY`
(syscall 5) looks up its CPtr there. So **every EL0 task names the same caps** — a
confused deputy (CORE-2/XC-6), and P12's defining property ("a publisher may not
subscribe" = a task holds `Topic{W}` but not `Topic{R}`) is *literally inexpressible*
because there is no per-task authority set to omit a cap from.

## Current shape (what exists)

- `caps::Cap` — `{otype, rights:u8 (R|W|G), base, size, watermark, parent:Option<usize>}` (~48 B).
- `caps::CapSpace` — `slots: [Option<Cap>; SLOTS]`, `SLOTS = 64` (~3 KB). Methods:
  `get(slot)`, `retype`, `revoke`, `mint`, `has_rights`, `as_frame_rights`.
- `scheduler` — per-TCB arrays indexed by `tid` (`SP/PRIO/ALIVE/BLOCKED/TTBR0/RESTART`,
  `MAX_THREADS = 8`), plus `current_tid()`.
- `main.rs` — `build_root_cspace()` fills `ROOT`; `SYS_CAP_IDENTIFY` resolves against `root()`.

## Target shape

Replace the single `ROOT` with a **per-TCB array**, keyed by the scheduler's `tid`,
mirroring how `RESTART`/`TTBR0` already live:

```rust
// in kernel (owns the policy) — one CSpace per scheduler slot.
static mut CSPACE: [Option<caps::CapSpace>; scheduler::MAX_THREADS] = [const { None }; _];
```

~24 KB of `.bss` (8 × 3 KB) — acceptable. (If tighter later: box into an untyped pool.)

- `cspace_of(tid) -> Option<&CapSpace>` / `_mut`, bounds-checked on `tid`.
- `current_cspace()` = `cspace_of(scheduler::current_tid())`.
- `SYS_CAP_IDENTIFY` (and any future cap syscall) resolves the CPtr against
  **`current_cspace()`**, never a global — so a task can only name caps IN ITS OWN space.
- `build_root_cspace()` builds into the boot/root TCB's slot (tid 0), not a global.
- **Grant/delegation**: to give an EL0 driver a cap, the spawner `mint`s a
  rights-narrowed copy from the root CSpace into the child TCB's CSpace slot at spawn
  time (rights can only narrow — `caps::mint` already enforces this). This is where
  "publisher gets `Topic{W}` only" becomes expressible.
- **Teardown**: on TCB kill (`scheduler::exit_current` / the fault-restart kill path),
  clear that tid's CSpace slot (drop its caps). Ties into CORE-1 (revoke → unmap):
  revoking a driver's Frame cap should also drop its mapping.

## The migration, minimal-risk order

1. Add `CSPACE[MAX_THREADS]` + `cspace_of`/`current_cspace` accessors (bounds-checked).
   Keep `root()` as `cspace_of(0)` during the transition so nothing else breaks.
2. `build_root_cspace()` → write into `CSPACE[0]` (the boot TCB). `root()` still works.
3. Point `SYS_CAP_IDENTIFY` at `current_cspace()`. On the QEMU P3 path the caller is
   the root task (tid 0), so behavior is unchanged and P3 stays green.
4. At each EL0 spawn (`el0_preempt_spawn`, the CM5 loop, later P11/P12 services): create
   a CSpace in that TCB's slot and `mint` exactly the caps it should hold (narrowed).
5. On kill: clear the slot.
6. Only THEN can P12 express "publisher ≠ subscriber" and P11 give a driver a
   rights-narrowed Frame cap set.

## What it unblocks / clears

- **P12** — per-task authority makes "may publish, may not subscribe" expressible.
- **P11** — the driver's grant set becomes a real per-TCB cap set (not ad-hoc `map_user_*`).
- **CORE-1/XC-5** — with mapping routed through caps AND per-TCB CSpaces, `revoke` can
  sever a specific driver's authority (this doc is the CSpace half; the "route mapping
  through cap invocation + revoke unmaps" half is CORE-1, landed alongside).
- **CORE-2/XC-6** — the confused-deputy global CSpace is gone.

## Risks / must-verify

- **Memory**: 24 KB `.bss`. Confirm the kernel image/`.bss` budget on both backends.
- **Resolution path**: `current_tid()` during a cooperative `enter_user` is the boot
  thread (tid 0) — so cooperative-stage cap ops resolve against the root CSpace, same as
  today. Verify no path resolves a cap while `CUR` points at a *different* TCB than the
  intended owner (the same subtlety CORE-6 handled for restart records).
- **revoke scoping**: `revoke` currently walks one CSpace's derivation tree. Per-TCB,
  a mint into a child crosses CSpaces — the CDT `parent` is a slot index with no
  CSpace tag (also CORE-9). For P12's minimal needs (static mint at spawn, drop on
  kill), whole-CSpace teardown is enough; cross-CSpace single-cap revoke needs CORE-9
  (generation-tagged, CSpace-tagged MDB) — sequence CORE-9 before dynamic revoke.

## Validation loop (how to prove it)

1. **No regression**: QEMU `validate.sh` P2 (caps) + P3 (`SYS_CAP_IDENTIFY`) stay green —
   the root task (tid 0) resolves its caps exactly as before.
2. **New gate `[P3-iso]`**: spawn a second EL0 TCB with a CSpace that does NOT hold a
   given CPtr; have it invoke `SYS_CAP_IDENTIFY` on that CPtr; assert it FAILS
   (RC_DENIED / not-found) while the root TCB SUCCEEDS on the same CPtr. That is the
   confused-deputy fix, demonstrated.
3. Metal: the P7c scheduled-EL0 TCB gets its own (minimal) CSpace; its `SYS_CAP_IDENTIFY`
   resolves only its own caps.

## Files

`kernel/src/caps.rs` (maybe a `CapSpace::clear()`), `kernel/src/main.rs` (CSPACE array +
accessors + build into tid 0 + SYS_CAP_IDENTIFY + per-spawn mint + kill clear),
`kernel/src/scheduler.rs` (expose MAX_THREADS if not already; a `current_tid` is present).
Sequence CORE-1 (mapping-through-caps + revoke-unmaps) alongside, and CORE-9
(generation/CSpace-tagged MDB) before any cross-CSpace single-cap revoke.
