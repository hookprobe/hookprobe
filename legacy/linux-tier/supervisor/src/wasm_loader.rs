//! Real Wasm loader — runs a capability-sandboxed module under Wasmtime (ADR 0009 build step 1).
//!
//! Replaces the reconcile-only `MockLoader`: a module is a WASI command that reads JSON-lines from
//! stdin and writes JSON alerts/scores to stdout. It receives NOTHING except:
//!   - its granted READ dirs (WASI preopens from `module.yaml` grants) — the capability sandbox,
//!   - a memory ceiling (`StoreLimits` from the module's budget),
//!   - an epoch deadline (a runaway module is interrupted, not left to hang).
//!
//! Built only with `--features wasm` (Wasmtime is a heavy dep; the reconcile tests stay light).
//!
//! ## AOT (`.cwasm`) trust model — honest note (ADR 0009 gap 1/2; ADR 0016 Fix A; ADR 0017 restores AOT)
//!
//! The existing cosign-style module signature (`module_sig.rs`) signs a digest of `module.yaml`
//! ONLY, not the compiled `.wasm`/`.cwasm` bytes directly — ADR 0016 closes that by having
//! `module.yaml` carry a payload digest the signature transitively covers. But a 2026-07-05 audit
//! found the FIRST implementation of that fix (`verify_artifact_digests`, re-opening the artifact
//! path to hash it) still had a critical hole: on a device with a writable-partition AOT cache
//! (`.cwasm`), an attacker who can write there could swap in a malicious `.cwasm` plus a sidecar
//! claiming the (untouched, real) `.wasm`'s hash — the digest check passed, because it hashed the
//! real file; Wasmtime then `deserialize_file`d the EVIL `.cwasm`. **Fix A: for
//! `signature: required` modules, the writable-cache `.cwasm` fast path (the `Executable` enum
//! below, and `DEVICE_CWASM_CACHE`) is UNREACHABLE, permanently.** The loader reads the pinned
//! `.wasm` bytes exactly ONCE, verifies THOSE bytes (path-binding + digest,
//! `module_sig::verify_executable_binding`) — this is the FLOOR, always safe, always available.
//!
//! **ADR 0017 adds a second, faster, EQUALLY authenticated path in front of that floor**: a
//! build-time-precompiled `.cwasm` shipped in the immutable RO rootfs (never `/var`), digest-
//! pinned in the SAME signed `module.yaml` under a `role: aot` entry (arch-qualified — one image
//! ships one arch's blob). `load_module_gated` looks for it via `locate_rootfs_aot` (RO install
//! dir ONLY), verifies the exact bytes about to be deserialized against that entry
//! (`module_sig::verify_aot_binding`), and only THEN `Module::deserialize`s them — never
//! `deserialize_file`, never a second open. Any doubt at all (absent, wrong arch, digest mismatch,
//! or a Wasmtime version/config-drift `deserialize` `Err`) falls straight through to the Fix A
//! floor; there is no code path from a failed AOT check to running the `.cwasm`. See
//! `load_module_gated`, `docs/adr/0016-artifact-hash-signing.md`, `docs/adr/0017-authenticated-aot-cache.md`.
use anyhow::{anyhow, Context, Result};
use hookprobe_manifest::module_def::{ArtifactRole, ModuleDef};
use hookprobe_manifest::module_sig;
use hookprobe_manifest::sd_notify::notify_ready;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(test))]
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline};
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

/// Store data: the WASI ctx + the resource limiter, both reachable from the store.
struct StoreState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// The ONE `Config` used everywhere (load, streaming, load-check, precompile). Wasmtime requires
/// the config used to precompile a `.cwasm` to match (compatibly) the config used to load it —
/// `epoch_interruption` must be on in both, or `Module::deserialize` refuses the artifact.
///
/// `consume_fuel` (resource-budgets feature, the wasm CPU-metering "soft/rate wall" — see
/// `hookprobe_manifest::resource_budget` module docs for the two-walls design and the fuel-per-
/// invocation-vs-per-epoch-tick fork flagged for an ADR) is likewise ALWAYS on here, for the same
/// reason: any `.cwasm` precompiled under a config that disagrees on `consume_fuel` fails to
/// deserialize under this one (safely — `load_module`/`load_module_gated` already treat a
/// deserialize `Err` as "fall back to JIT", never a crash). A `.cwasm` shipped from BEFORE this
/// change was added will therefore take one extra JIT-compile fallback until the builder
/// re-precompiles it — expected, logged (`record_aot_fallback`), never unsafe.
fn engine_config() -> Config {
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.consume_fuel(true);
    config
}

/// A module's resolved executable: either a verified-compatible precompiled `.cwasm` (fast path,
/// ADR 0009's ~1-5ms cold start) or the `.wasm` source (JIT-compiled at load — always safe, always
/// available as a fallback).
#[derive(Debug, Clone)]
pub enum Executable {
    /// `.cwasm` whose sidecar hash matches `source_wasm`'s current bytes (see module doc).
    Precompiled { cwasm: PathBuf, source_wasm: PathBuf },
    /// The `.wasm` source; compiled fresh (JIT) on load.
    Source(PathBuf),
}

impl Executable {
    pub fn describe(&self) -> &'static str {
        match self {
            Executable::Precompiled { .. } => "precompiled (.cwasm, AOT)",
            Executable::Source(_) => "source (.wasm, JIT)",
        }
    }

    /// The path actually fed to Wasmtime (the `.cwasm` if precompiled, else the `.wasm`).
    pub fn display_path(&self) -> &Path {
        match self {
            Executable::Precompiled { cwasm, .. } => cwasm,
            Executable::Source(wasm) => wasm,
        }
    }

    /// Like `describe()`, but honest about what `load_module_gated` ACTUALLY compiles for this
    /// module: for `signature: required`, THIS `Executable`'s own `.cwasm` field (however it
    /// resolved — the writable-cache/dev-workspace convention) is NEVER touched; the loader
    /// always verifies+compiles from the pinned `.wasm` (ADR 0016 Fix A's floor), and MAY
    /// additionally use an independently-located, RO-rootfs, manifest-digest-verified `.cwasm`
    /// fast path (ADR 0017) that has nothing to do with this enum's own `.cwasm` field. Logging
    /// `exec.describe()` unconditionally would call this path "precompiled (.cwasm, AOT)" (or
    /// claim the ADR 0017 fast path never runs) — misleading either way. Callers that log what a
    /// module actually ran should use this (and `display_path_gated`) instead of the raw
    /// `describe`/`display_path`; the definitive per-load outcome (AOT fast path used, or which
    /// fallback reason) is logged directly by `load_module_gated` at call time.
    pub fn describe_gated(&self, def: &ModuleDef) -> &'static str {
        if def.signature == "required" {
            "verified (ADR 0016 .wasm floor + ADR 0017 authenticated AOT fast path when available)"
        } else {
            self.describe()
        }
    }

    /// The path `load_module_gated` ACTUALLY compiles from — `source_wasm()` for a `required`
    /// module (the `.cwasm` field is inert on that path), else whatever `display_path()` says.
    pub fn display_path_gated(&self, def: &ModuleDef) -> &Path {
        if def.signature == "required" {
            self.source_wasm()
        } else {
            self.display_path()
        }
    }

    /// The SOURCE `.wasm` this executable is bound to — for `Precompiled`, the `.wasm` its
    /// `.cwasm` sidecar binds to; for `Source`, itself. ADR 0016 pins this file (never the
    /// `.cwasm`): the `.cwasm` is device-local/writable (produced by `precompile()` on the
    /// writable partition) and is already transitively bound to the source `.wasm` by its own
    /// sha256 sidecar (`cwasm_matches_source`) — signing the source once covers both.
    pub fn source_wasm(&self) -> &Path {
        match self {
            Executable::Precompiled { source_wasm, .. } => source_wasm,
            Executable::Source(wasm) => wasm,
        }
    }
}

/// Load a `Module` from a resolved `Executable`. A `.cwasm` that fails to deserialize (Wasmtime
/// version/target mismatch, corruption) is NEVER a hard error — fall back to compiling the source
/// `.wasm` fresh, with a warning on stderr. Never crash on a stale AOT cache.
fn load_module(engine: &Engine, exec: &Executable) -> Result<Module> {
    match exec {
        Executable::Precompiled { cwasm, source_wasm } => {
            // SAFETY: the `.cwasm` was produced by our own `precompile()` and is bound to
            // `source_wasm`'s exact bytes via the sha256 sidecar checked in `locate_executable`;
            // Wasmtime additionally validates its own version/target header at deserialize time
            // and returns an Err (not UB) on a genuine mismatch — handled below, not unwrapped.
            match unsafe { Module::deserialize_file(engine, cwasm) } {
                Ok(m) => Ok(m),
                Err(e) => {
                    eprintln!(
                        "warning: .cwasm {} failed to deserialize ({e:#}) — falling back to compiling {} from source",
                        cwasm.display(),
                        source_wasm.display()
                    );
                    Module::from_file(engine, source_wasm)
                        .with_context(|| format!("load {}", source_wasm.display()))
                }
            }
        }
        Executable::Source(wasm) => {
            Module::from_file(engine, wasm).with_context(|| format!("load {}", wasm.display()))
        }
    }
}

/// ADR 0017 residual-risk #1 — boot-time telemetry: how many times THIS supervisor process fell
/// back from the verified-AOT fast path to the verified-JIT floor, for ANY `signature: required`
/// module, for ANY reason (absent blob, wrong/absent arch, digest mismatch, unreadable blob, or a
/// Wasmtime version/config-drift `deserialize` `Err`). A healthy device is 0 for every module this
/// image ships an AOT blob for; a nonzero count is exactly the signal that would otherwise be a
/// SILENT ~1000x regression (ADR 0017 Blocker: embedded-vs-CLI Wasmtime drift) — surfaced as data
/// instead of a mystery slow boot. Process-lifetime (resets every boot/run, like the process
/// itself — a fresh supervisor invocation IS a fresh boot-time window).
// Production: a process-lifetime atomic — the correct shape for a boot-time telemetry counter that
// aggregates fallbacks across every module the reconcile loop loads.
#[cfg(not(test))]
static AOT_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

// Test: the counter is THREAD-LOCAL. `cargo test` runs this file's tests concurrently, and
// `load_module_gated` (the only writer) is called synchronously on each test's own thread — so a
// thread-local sees exactly, and only, that test's own fallbacks. This makes the counter
// assertions race-free by construction with no cross-test lock (previously an easy-to-forget
// Mutex only some tests remembered to take, which flaked when an unlocked test raced the global).
#[cfg(test)]
thread_local! {
    static AOT_FALLBACK_COUNT_TL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Current value of the ADR 0017 AOT-\>JIT fallback counter.
#[cfg(not(test))]
pub fn aot_fallback_count() -> u64 {
    AOT_FALLBACK_COUNT.load(Ordering::Relaxed)
}
#[cfg(test)]
pub fn aot_fallback_count() -> u64 {
    AOT_FALLBACK_COUNT_TL.with(|c| c.get())
}

/// Test-only: reset the (thread-local) counter between independent test cases.
#[cfg(test)]
fn reset_aot_fallback_count_for_test() {
    AOT_FALLBACK_COUNT_TL.with(|c| c.set(0));
}

fn record_aot_fallback(module_id: &str, arch: &str, reason: &str) {
    #[cfg(not(test))]
    let n = AOT_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    #[cfg(test)]
    let n = AOT_FALLBACK_COUNT_TL.with(|c| {
        let v = c.get() + 1;
        c.set(v);
        v
    });
    eprintln!(
        "telemetry: aot_fallback_total={n} module={module_id} arch={arch} reason={reason} (ADR 0017)"
    );
}

/// ADR 0017 D2 / ADR 0021 — locate the module's RO-rootfs AOT blob for a given (`arch`, `cpu`)
/// tier, under `install_dir` (`/usr/lib/hookprobe/modules/<id>/` on a real device — the caller
/// MUST pass the module's OWN install dir here, and MUST NEVER pass `DEVICE_CWASM_CACHE`; that
/// writable cache is dead for `signature: required` modules, permanently — this function has no
/// knowledge of it at all, so there is no way to accidentally wire it back in here).
///
/// **Data-driven filename (ADR 0021):** the blob's on-disk name is NOT built here from `<id>` —
/// it is READ from the signed `module.yaml`'s `role: aot` entry that matches (`arch`, `cpu`)
/// exactly (so the baseline entry `path: napse.cwasm` and the A76 entry `path: napse.a76.cwasm`,
/// `cpu: cortex-a76` each resolve to their own file, straight from the manifest the release signed
/// — no filename convention is hardcoded in Rust). `cpu: None` selects ONLY the baseline entry
/// (no `cpu:` field); `cpu: Some("cortex-a76")` selects ONLY the matching-tier entry.
///
/// Returns `None` (never an error) on ANY doubt — no matching entry, an absolute/traversal path
/// (defensive: an AOT blob is always co-located), absent file, a symlink, or a path that would
/// resolve outside `install_dir` — so the caller always has a safe "fall back to verified JIT"
/// (or to the next, less-specific tier) branch.
fn locate_rootfs_aot(def: &ModuleDef, install_dir: &Path, arch: &str, cpu: Option<&str>) -> Option<PathBuf> {
    // Find the declared aot entry for exactly (arch, cpu) and take ITS path — never guess a name.
    let rel = def.artifacts.iter().find(|a| {
        a.role == ArtifactRole::Aot
            && a.arch.as_deref().map(|ar| ar.eq_ignore_ascii_case(arch)).unwrap_or(false)
            && match (cpu, a.cpu.as_deref()) {
                (None, None) => true,
                (Some(want), Some(have)) => want.eq_ignore_ascii_case(have),
                _ => false,
            }
    })?;
    let rel_path = rel.path.as_str();
    // An AOT blob is co-located under install_dir; a role: aot path must be relative + traversal-free.
    if rel_path.is_empty() || rel_path.starts_with('/') || rel_path.contains('\\') || rel_path.contains("..") {
        return None;
    }
    let candidate = install_dir.join(rel_path);
    let meta = std::fs::symlink_metadata(&candidate).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None; // never follow a symlink; verify_aot_binding re-checks this too, but fail
                      // closed at the very first opportunity rather than reading through one
    }
    let install_canon = std::fs::canonicalize(install_dir).ok()?;
    let candidate_canon = std::fs::canonicalize(&candidate).ok()?;
    if !candidate_canon.starts_with(&install_canon) {
        return None; // must stay within the module's own install dir
    }
    Some(candidate_canon)
}

/// ADR 0016 Fix A floor + ADR 0017 authenticated-AOT fast path — the ONLY load path used for
/// `signature: required` modules.
///
/// 1. Reads the pinned `.wasm` bytes EXACTLY ONCE, verifies those exact bytes (path-binding +
///    digest — `module_sig::verify_executable_binding`, closing ADR 0016 Findings 1 and 3).
/// 2. **ADR 0017/0021 fast path (per-CPU-tier).** For each candidate tier — MOST SPECIFIC FIRST
///    (`cpu_tier` from the signed Platform Manifest, e.g. `Some("cortex-a76")` on an rpi5/rk3588,
///    then always the baseline `None`) — looks for that tier's `.cwasm` in the RO rootfs
///    (`locate_rootfs_aot`, which reads the blob's filename straight from the signed `role: aot`
///    entry for (arch, cpu) — NEVER `DEVICE_CWASM_CACHE`); if present, reads it ONCE and verifies
///    those exact bytes against that same entry (`module_sig::verify_aot_binding`). Only on a
///    clean verify does it `Module::deserialize` the verified in-memory bytes — never
///    `deserialize_file`, no second open between check and load (same TOCTOU discipline as step 1).
///    The FIRST tier that locates+verifies+deserializes wins. **Fail-closed selection:** the A76
///    candidate is only ever ATTEMPTED when the manifest says A76 — an A76 blob is never loaded on
///    an A72 (it would trap on an illegal LSE instruction); the baseline is always the last, safe
///    resort. If NO tier succeeds, records ONE ADR 0017 fallback (`record_aot_fallback`, with the
///    baseline tier's failure reason) and falls through to step 3 — there is NO code path from a
///    failed AOT check to executing a `.cwasm`.
/// 3. **The floor.** Compiles the ALREADY-VERIFIED `.wasm` bytes from step 1
///    (`Module::from_binary`) — slow, but always safe, always available.
///
/// `exec`'s own `.cwasm` field (the writable-cache/dev-workspace convention `locate_executable`
/// resolved) is never even looked at on this branch — `Module::deserialize_file` stays
/// UNREACHABLE for a signed module, however `locate_executable` resolved `exec`, closing the
/// writable-partition `.cwasm`-swap TOCTOU for good (ADR 0016 Fix A, unchanged by ADR 0017).
///
/// For a `signature: unsigned` (dev-only) module — which never claimed ADR 0016/0017 payload
/// protection — this falls back to the ORIGINAL behavior: any declared artifact digests are
/// still checked (unconditionally, same as always), and the `.cwasm` AOT fast path stays
/// reachable via `load_module` (the writable-cache/sidecar-hash convention).
pub fn load_module_gated(
    engine: &Engine,
    exec: &Executable,
    def: &ModuleDef,
    install_dir: &Path,
    events_path: Option<&Path>,
    cpu_tier: Option<&str>,
) -> Result<Module> {
    if def.signature == "required" {
        let wasm_path = exec.source_wasm();
        let bytes = std::fs::read(wasm_path)
            .with_context(|| format!("reading {} for the ADR 0016 verified-load path", wasm_path.display()))?;
        module_sig::verify_executable_binding(def, install_dir, wasm_path, &bytes, events_path)
            .with_context(|| format!("refusing to load {}: ADR 0016 artifact-digest check failed", def.id))?;

        // ADR 0017 D2 / ADR 0021 — verified AOT fast path, IN FRONT of the ADR 0016 Fix A floor
        // below. Try each CPU-microarch tier most-specific-first: the manifest's `cpu_tier` (only
        // present, hence only attempted, when the SIGNED manifest actually classifies this device
        // as that tier — never an A76 blob on an A72), then always the arch baseline. The first
        // tier whose blob locates + digest-verifies + deserializes wins; only if NONE do we fall
        // through to the verified-JIT floor, recording exactly ONE fallback (the baseline tier's
        // reason — the meaningful "why did we end up JIT" signal).
        let arch = module_sig::running_arch();
        let mut tiers: Vec<Option<&str>> = Vec::with_capacity(2);
        if let Some(t) = cpu_tier {
            tiers.push(Some(t)); // e.g. Some("cortex-a76") on rpi5/rk3588
        }
        tiers.push(None); // the arch baseline — always the safe floor, always attempted last

        let mut fallback_reason = "absent";
        for &tier in &tiers {
            let tier_label = tier.unwrap_or("baseline");
            match locate_rootfs_aot(def, install_dir, arch, tier) {
                Some(aot_path) => match std::fs::read(&aot_path) {
                    Ok(aot_bytes) => match module_sig::verify_aot_binding(def, install_dir, arch, tier, &aot_path, &aot_bytes, events_path) {
                        Ok(()) => {
                            // SAFETY: `aot_bytes` were just digest-verified, in memory, against the
                            // `role: aot` entry for THIS (arch, cpu) inside the SIGNED module.yaml —
                            // exactly as trustworthy as compiling the sibling `.wasm` below, ~1000x
                            // faster. `Module::deserialize` (never `_file`) on the SAME bytes just
                            // checked — no second open, no TOCTOU window.
                            match unsafe { Module::deserialize(engine, &aot_bytes) } {
                                Ok(m) => {
                                    eprintln!(
                                        "info: {}: AOT fast path — deserialized verified {} ({} bytes, arch {arch}, cpu {tier_label}) (ADR 0017/0021)",
                                        def.id, aot_path.display(), aot_bytes.len()
                                    );
                                    return Ok(m);
                                }
                                Err(e) => {
                                    eprintln!(
                                        "warning: {}: AOT .cwasm (cpu {tier_label}) failed to deserialize ({e:#}) — \
                                         Wasmtime version/config drift? trying next tier / verified JIT (ADR 0017)",
                                        def.id
                                    );
                                    fallback_reason = "deserialize_error";
                                }
                            }
                        }
                        Err(e) => {
                            // verify_aot_binding already emitted ArtifactTamper on an actual digest
                            // MISMATCH (never on mere absence) — either way, fail closed to the next
                            // tier / the floor.
                            eprintln!("note: {}: AOT fast path (cpu {tier_label}) unavailable ({e:#}) — trying next tier / verified JIT", def.id);
                            fallback_reason = "verify_failed";
                        }
                    },
                    Err(e) => {
                        eprintln!("warning: {}: could not read AOT blob {aot_path:?} (cpu {tier_label}) ({e:#}) — trying next tier / verified JIT", def.id);
                        fallback_reason = "read_error";
                    }
                },
                None => {
                    // No blob for this tier — normal for the A76 candidate on an image that ships
                    // only the baseline; keep the baseline tier's reason as the reported one.
                    if tier.is_none() {
                        fallback_reason = "absent";
                    }
                }
            }
        }

        // No AOT tier succeeded → the verified-JIT floor. Record exactly one fallback.
        record_aot_fallback(&def.id, arch, fallback_reason);
        return Module::from_binary(engine, &bytes)
            .with_context(|| format!("compiling {} from ADR-0016-verified bytes", wasm_path.display()));
    }

    // signature: unsigned (dev/local, never claimed payload protection) — legacy behavior: any
    // DECLARED artifact digest is still checked unconditionally, and the .cwasm AOT fast path
    // (when present and sidecar-bound) is honored.
    module_sig::verify_artifact_digests(def, install_dir, events_path)
        .with_context(|| format!("ADR 0016 artifact-digest check failed for {}", def.id))?;
    load_module(engine, exec)
}

/// True iff `e` is (or wraps) a Wasmtime `Trap::OutOfFuel` — the wasm CPU-metering wall
/// (resource-budgets feature) tripping, distinct from every other trap/exit reason. Checked via
/// `downcast_ref` the same way `wasmtime_wasi::I32Exit` already is above/below — no new dependency.
fn is_out_of_fuel(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel)
}

/// Run an ALREADY-LOADED `Module` to completion, capturing stdout — the shared tail
/// `run_wasi_module` uses, and also reused directly by the ADR 0016 Fix A regression test (which
/// needs to run a `Module` obtained via `load_module_gated`, not `Module::from_file`, to prove
/// the gated path never executes a swapped `.cwasm`).
///
/// `fuel_budget` (resource-budgets feature): the wasm CPU-metering wall, ONE budget for this
/// entire invocation (as opposed to the streaming path's per-epoch-tick refill — see
/// `hookprobe_manifest::resource_budget` module docs for the fork). Exhaustion is a bounded,
/// ACCOUNTED failure — the module is cleanly terminated (a Wasmtime trap), never left to hang or
/// silently keep consuming CPU; the returned `Err`'s message names it explicitly so callers/logs
/// don't have to guess "trapped" vs. "ran out of budget".
fn run_loaded_module(
    engine: &Engine,
    module: &Module,
    preopens: &[(String, String)],
    stdin: Vec<u8>,
    memory_mb: u64,
    timeout: Duration,
    fuel_budget: u64,
) -> Result<Vec<u8>> {
    let stdout = MemoryOutputPipe::new(4 << 20); // 4 MiB cap on captured output
    let mut builder = WasiCtxBuilder::new();
    builder
        .stdin(MemoryInputPipe::new(stdin))
        .stdout(stdout.clone())
        .inherit_stderr();
    for (host, guest) in preopens {
        builder
            .preopened_dir(host, guest, DirPerms::READ, FilePerms::READ)
            .with_context(|| format!("preopen {host} -> {guest}"))?;
    }
    let wasi = builder.build_p1();

    let limits = StoreLimitsBuilder::new()
        .memory_size((memory_mb.max(1) as usize) * 1024 * 1024)
        .build();
    let mut store = Store::new(engine, StoreState { wasi, limits });
    store.limiter(|s| &mut s.limits);
    // Resource-budgets feature: the wasm CPU-metering wall. `engine_config()` always enables
    // `consume_fuel`, so every Store MUST have its fuel set before running or Wasmtime traps
    // immediately (0 fuel is the Store default) — this IS the budget, not a workaround for one.
    store.set_fuel(fuel_budget).context("set_fuel (resource-budgets: consume_fuel must be on)")?;

    // Epoch deadline: one tick allowed; a watchdog thread bumps the epoch after `timeout`, which
    // interrupts a module that runs too long (the per-tick budget is the streaming-mode follow-on).
    store.set_epoch_deadline(1);
    let engine_wd = engine.clone();
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        engine_wd.increment_epoch();
    });

    let mut linker: Linker<StoreState> = Linker::new(engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi)
        .context("link wasi")?;
    let instance = linker
        .instantiate(&mut store, module)
        .context("instantiate")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("module has no _start (not a WASI command?)")?;

    match start.call(&mut store, ()) {
        Ok(()) => {}
        Err(e) if is_out_of_fuel(&e) => {
            return Err(anyhow!(
                "hookprobe: wasm fuel budget exhausted (budget={fuel_budget} units) — module invocation terminated (bounded, accounted failure)"
            ));
        }
        Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) if exit.0 == 0 => {} // clean WASI exit(0)
            Some(exit) => return Err(anyhow!("module exited with code {}", exit.0)),
            None => return Err(e).context("module trapped"),
        },
    }
    drop(store);
    Ok(stdout.contents().to_vec())
}

/// Run a WASI module to completion. `stdin` is fed in; captured stdout is returned. `preopens` are
/// (host, guest) READ dirs (the module's grants). `memory_mb` caps linear memory; `timeout` bounds
/// wall-clock via an epoch deadline; `fuel_budget` bounds CPU computation for this ONE invocation
/// (resource-budgets feature — see `run_loaded_module`/`hookprobe_manifest::resource_budget`).
/// A clean WASI exit(0) is success; any other exit/trap (including fuel exhaustion) is an error.
#[allow(dead_code)] // the one-shot runner: used by tests; production uses the streaming path.
pub fn run_wasi_module(
    wasm: &Path,
    preopens: &[(String, String)],
    stdin: Vec<u8>,
    memory_mb: u64,
    timeout: Duration,
    fuel_budget: u64,
) -> Result<Vec<u8>> {
    let engine = Engine::new(&engine_config()).context("wasmtime engine")?;
    let module =
        Module::from_file(&engine, wasm).with_context(|| format!("load {}", wasm.display()))?;
    run_loaded_module(&engine, &module, preopens, stdin, memory_mb, timeout, fuel_budget)
}

/// Run a WASI module in STREAMING mode: inherit the process stdin/stdout/stderr so it slots into a
/// `tail -F flows | hookprobe-supervisor --run-wasm napse >> events` systemd pipeline (replacing the
/// native binary). This is the PRODUCTION run path — the sandboxed engine as the live SOC datapath.
///
/// Epoch interruption is ALWAYS on (a wedged module must not hang the unit forever): a ticker thread
/// bumps the engine epoch every `epoch_ms` (from `module.yaml`'s `resources.epoch_ms`), and the
/// deadline callback returns `Continue(1)` each tick so a healthy long-running stream keeps going —
/// UNLESS `kill` is set, in which case the callback traps the module on its next epoch check.
/// `kill` is a manual kill-switch for tests today; production relies on systemd's normal
/// `SIGTERM`→`TimeoutStopSec`→`SIGKILL` unit-stop sequence (see module doc — no signal-handling dep
/// was added to keep this a zero-new-dependency change).
///
/// `fuel_budget` (resource-budgets feature): a LONG-RUNNING stream never "completes" one invocation
/// the way a batch run does, so a single lifetime fuel budget would either exhaust almost
/// immediately or have to be unboundedly large to mean anything. Instead this REFILLS the budget
/// on every epoch tick, from inside the SAME `epoch_deadline_callback` the wall-clock wall already
/// uses (no extra thread/lock — `StoreContextMut::set_fuel` is only safe to call from the
/// executing thread, which is exactly where this callback runs) — turning `fuel` into a rate wall:
/// "at most `fuel_budget` units of wasm computation per `epoch_ms` window". Exhaustion mid-tick
/// traps the module immediately (Wasmtime checks fuel at every fuel-charged instruction, not just
/// at epoch boundaries) with a message naming it explicitly, same as the one-shot path — a
/// bounded, accounted failure the unit's `Restart=on-failure`/`RestartSec=` picks up. This is the
/// pragmatic design choice flagged for an ADR in `hookprobe_manifest::resource_budget`'s module
/// docs (a "lifetime budget, must restart to reset" policy is an equally defensible alternative).
///
/// **sd_notify watchdog (backend-audit gap 2 — Architecture.md §4.4; TA2 fix 2026-07-17)**: `READY=1`
/// fires once instantiation succeeds, right before the module starts running. `WATCHDOG=1` is driven
/// by a dedicated TIMER thread (interval = `WATCHDOG_USEC`/2), NOT from the `epoch_deadline_callback`.
/// The earlier epoch-callback design pinged only while the guest executed wasm, which was BACKWARDS
/// for a streaming reflex module: an idle module blocked on stdin (a quiet network — perfectly
/// healthy) sent no ping and was SIGABRT-killed every `WatchdogSec` (dnsxai/aegis-guard were observed
/// crash-looping on Pi4+CM5), while a guest wedged in a compute loop kept hitting the callback (and
/// being refueled) and so kept the unit alive. For these modules "blocked on input" is health, so a
/// timer heartbeat proving the supervisor process + host runtime are alive is the correct liveness
/// signal; a genuinely compute-wedged guest is bounded by the epoch/fuel wall, not this ping. Each
/// unit's `WatchdogSec=` therefore only needs to exceed the heartbeat interval, not the input-idle gap.
pub fn run_wasi_module_streaming(
    exec: &Executable,
    def: &ModuleDef,
    install_dir: &Path,
    events_path: Option<&Path>,
    preopens: &[(String, String)],
    memory_mb: u64,
    epoch_ms: u64,
    fuel_budget: u64,
    kill: Arc<AtomicBool>,
    cpu_tier: Option<&str>,
) -> Result<()> {
    let engine = Engine::new(&engine_config()).context("wasmtime engine")?;
    let module = load_module_gated(&engine, exec, def, install_dir, events_path, cpu_tier)?;
    let mut builder = WasiCtxBuilder::new();
    builder.inherit_stdin().inherit_stdout().inherit_stderr();
    for (host, guest) in preopens {
        builder.preopened_dir(host, guest, DirPerms::READ, FilePerms::READ)?;
    }
    let wasi = builder.build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size((memory_mb.max(1) as usize) * 1024 * 1024)
        .build();
    let mut store = Store::new(&engine, StoreState { wasi, limits });
    store.limiter(|s| &mut s.limits);
    // Resource-budgets feature: the first tick's fuel allowance (topped up again on every
    // subsequent epoch tick below — see the fn doc's "rate wall" design note).
    store.set_fuel(fuel_budget).context("set_fuel (resource-budgets: consume_fuel must be on)")?;

    // Epoch ticker: increments the engine epoch every `epoch_ms`. Detached (not joined) — it dies
    // with the process, matching the existing watchdog pattern in `run_wasi_module`.
    let engine_wd = engine.clone();
    let tick = Duration::from_millis(epoch_ms.max(1));
    std::thread::spawn(move || loop {
        std::thread::sleep(tick);
        engine_wd.increment_epoch();
    });
    let module_id = def.id.clone();
    store.epoch_deadline_callback(move |mut ctx| {
        if kill.load(Ordering::Relaxed) {
            anyhow::bail!("hookprobe: epoch kill-switch set — terminating module");
        }
        // Refuel: resets this tick's CPU-computation allowance regardless of how much of the
        // previous tick's fuel is left (a healthy module that used little fuel doesn't "bank" it —
        // simple, predictable, matches the epoch wall's own "one tick at a time" semantics).
        if let Err(e) = ctx.set_fuel(fuel_budget) {
            eprintln!("warning: {module_id}: failed to refuel on epoch tick: {e:#}");
        }
        Ok(UpdateDeadline::Continue(1))
    });
    store.set_epoch_deadline(1);

    // TA2 (2026-07-17 field audit): drive WATCHDOG=1 from a dedicated TIMER thread, NOT from the
    // epoch callback. The old design pinged inside the epoch_deadline_callback above, which fires
    // ONLY while the guest is executing wasm — so a streaming module legitimately BLOCKED on stdin
    // (the common quiet-network idle case) sent no ping and systemd SIGABRT'd it every WatchdogSec.
    // Observed live: dnsxai (900s) + aegis-guard (1800s) crash-looping on Pi4+CM5, invisible to
    // `systemctl is-active` because each poll caught them just-restarted. The old approach was also
    // BACKWARDS: a guest wedged in a compute loop keeps hitting the epoch callback (and gets refueled
    // forever), so it would have kept pinging — the watchdog killed the healthy case and spared the
    // wedged one. For these modules "blocked on input" IS health; a timer heartbeat proving the
    // supervisor process + host runtime are alive is the correct signal, and a compute-wedged guest
    // is bounded by the epoch/fuel wall, not this ping. Detached (dies with the process), interval =
    // WATCHDOG_USEC/2 (or nothing when systemd set no watchdog).
    if let Some(interval) = hookprobe_manifest::sd_notify::watchdog_interval() {
        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            hookprobe_manifest::sd_notify::notify_watchdog();
        });
    }

    let mut linker: Linker<StoreState> = Linker::new(&engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi).context("link wasi")?;
    let instance = linker.instantiate(&mut store, &module).context("instantiate")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("no _start")?;
    // Startup succeeded (module instantiated, entry point resolved) — tell systemd we're ready
    // BEFORE the (potentially long-running / blocking-on-stdin) call below, matching Type=notify's
    // contract (see the fn doc's "sd_notify watchdog" note).
    notify_ready();
    match start.call(&mut store, ()) {
        Ok(()) => Ok(()),
        Err(e) if is_out_of_fuel(&e) => Err(anyhow!(
            "hookprobe: {}: wasm fuel budget exhausted ({fuel_budget} units/tick) — module invocation terminated (bounded, accounted failure)",
            def.id
        )),
        Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) if exit.0 == 0 => Ok(()),
            Some(exit) => Err(anyhow!("module exited {}", exit.0)),
            None => Err(e).context("module trapped"),
        },
    }
}

/// Locate a module's built `.wasm` (dev workspace target / on-device install / co-located).
pub fn locate_wasm(id: &str, modules_dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(root) = modules_dir.parent() {
        candidates.push(root.join(format!("target/wasm32-wasip1/release/{id}.wasm")));
    }
    candidates.push(PathBuf::from(format!("/usr/lib/hookprobe/modules/{id}.wasm")));
    candidates.push(modules_dir.join(id).join(format!("{id}.wasm")));
    candidates.into_iter().find(|p| p.exists())
}

/// The writable, device-local AOT cache (persistent data partition, NOT the immutable rootfs —
/// `/usr/lib` cannot be written to on a bootc image). Historically (ADR 0009) this was first-boot
/// precompiled on-device because cross-arch precompile at build time was judged too fragile to
/// validate without target hardware; ADR 0017 found that objection moot (the `build` stage
/// already runs AS the target arch, QEMU-emulated, so precompile there is native, not cross) and
/// moved the AUTHENTICATED path inside the RO rootfs (see `locate_rootfs_aot`,
/// `module_sig::verify_aot_binding`). This writable cache is now DEAD for `signature: required`
/// modules (ADR 0016 Fix A never trusted it either) — it remains reachable ONLY via
/// `locate_executable`/`load_module` for `signature: unsigned` (dev-only) modules, and
/// `hookprobe-precompile.service` is scoped to those (ADR 0017 D4).
pub const DEVICE_CWASM_CACHE: &str = "/var/lib/hookprobe/modules-cache";

fn sidecar_path(cwasm: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sha256", cwasm.display()))
}

/// Locate a module's best executable: a `.cwasm` bound (via sha256 sidecar) to the CURRENT `.wasm`
/// on disk, else the `.wasm` source. Checked, in order: a `.cwasm` sibling of the resolved `.wasm`
/// (dev workspace / co-located layouts, where that directory is writable), then the writable
/// on-device cache keyed by module id (the RO-image case, where a `.wasm` sibling can't be written).
/// A `.cwasm` whose sidecar is missing, unreadable, or mismatched is SKIPPED (not trusted) — the
/// caller falls through to a later candidate, and ultimately to the always-safe `.wasm` source.
pub fn locate_executable(id: &str, modules_dir: &Path) -> Option<Executable> {
    let wasm = locate_wasm(id, modules_dir)?;
    let sibling_cwasm = wasm.with_extension("cwasm");
    let cache_cwasm = PathBuf::from(DEVICE_CWASM_CACHE).join(format!("{id}.cwasm"));
    for cwasm in [sibling_cwasm, cache_cwasm] {
        if !cwasm.is_file() {
            continue;
        }
        if cwasm_matches_source(&cwasm, &wasm) {
            return Some(Executable::Precompiled { cwasm, source_wasm: wasm });
        }
    }
    Some(Executable::Source(wasm))
}

/// True iff `cwasm`'s sidecar `.cwasm.sha256` records the SHA-256 of `wasm`'s CURRENT bytes.
fn cwasm_matches_source(cwasm: &Path, wasm: &Path) -> bool {
    let Ok(recorded) = std::fs::read_to_string(sidecar_path(cwasm)) else {
        return false;
    };
    let Ok(wasm_bytes) = std::fs::read(wasm) else {
        return false;
    };
    let actual = hex::encode(Sha256::digest(&wasm_bytes));
    recorded.trim().eq_ignore_ascii_case(&actual)
}

/// Precompile report: what got written and how long native (JIT) compilation vs. this AOT step took.
#[derive(Debug)]
pub struct PrecompileReport {
    pub cwasm: PathBuf,
    pub cwasm_bytes: usize,
    pub compile_elapsed: Duration,
}

/// Precompile `wasm` to Wasmtime's native `.cwasm` (ADR 0009's ~1-5ms cold-start target — no JIT at
/// load time). Writes `<out_dir>/<id>.cwasm` plus a `<out_dir>/<id>.cwasm.sha256` sidecar recording
/// the SHA-256 of the SOURCE `.wasm` bytes — `locate_executable` refuses any `.cwasm` whose sidecar
/// doesn't match the `.wasm` currently on disk (see module doc for the honest trust-model note).
/// The `Config` here MUST match `engine_config()` (used everywhere modules are loaded) — Wasmtime
/// embeds config/version/target compatibility info in the `.cwasm` header and refuses a mismatch.
pub fn precompile(wasm: &Path, out_dir: &Path, id: &str) -> Result<PrecompileReport> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {out_dir:?}"))?;
    let wasm_bytes =
        std::fs::read(wasm).with_context(|| format!("reading {}", wasm.display()))?;
    let engine = Engine::new(&engine_config()).context("wasmtime engine")?;

    let started = std::time::Instant::now();
    let cwasm_bytes = engine
        .precompile_module(&wasm_bytes)
        .with_context(|| format!("precompiling {}", wasm.display()))?;
    let compile_elapsed = started.elapsed();

    let cwasm_path = out_dir.join(format!("{id}.cwasm"));
    std::fs::write(&cwasm_path, &cwasm_bytes)
        .with_context(|| format!("writing {cwasm_path:?}"))?;
    let digest = hex::encode(Sha256::digest(&wasm_bytes));
    std::fs::write(sidecar_path(&cwasm_path), digest)
        .with_context(|| format!("writing {:?}", sidecar_path(&cwasm_path)))?;

    Ok(PrecompileReport {
        cwasm: cwasm_path,
        cwasm_bytes: cwasm_bytes.len(),
        compile_elapsed,
    })
}

/// Load-check: load the module, satisfy WASI with EXACTLY its grants, instantiate, and verify the
/// `_start` entry — WITHOUT running it (no side effects). Proves the module is loadable under Wasmtime
/// with its declared capability sandbox + memory budget. Also returns the wall-clock cold-start cost
/// (Module load/deserialize only — NOT instantiation/verification) so callers can report real numbers.
/// The streaming run is `run_wasi_module_streaming`. UNGATED (no ADR 0016 digest/binding check) —
/// production call sites use `load_check_gated` below; this raw variant stays for cold-start
/// benchmarking (the Fix A regression measurement compares gated vs. this).
#[allow(dead_code)] // used by wasm_loader's own benchmark/regression tests, not production code.
pub fn load_check(exec: &Executable, preopens: &[(String, String)], memory_mb: u64) -> Result<Duration> {
    let engine = Engine::new(&engine_config())?;
    let started = std::time::Instant::now();
    let module = load_module(&engine, exec)?;
    let cold_start = started.elapsed();
    instantiate_and_check(&engine, &module, preopens, memory_mb)?;
    Ok(cold_start)
}

/// Same as `load_check`, but through the ADR 0016 Fix A gated load path
/// (`load_module_gated`) — the one the production reconcile/`--run-wasm` paths actually use.
/// Used by both production call sites (so their reported cold-start numbers reflect what really
/// executes) and by the Fix A cold-start regression measurement.
pub fn load_check_gated(
    exec: &Executable,
    def: &ModuleDef,
    install_dir: &Path,
    events_path: Option<&Path>,
    preopens: &[(String, String)],
    memory_mb: u64,
    cpu_tier: Option<&str>,
) -> Result<Duration> {
    let engine = Engine::new(&engine_config())?;
    let started = std::time::Instant::now();
    let module = load_module_gated(&engine, exec, def, install_dir, events_path, cpu_tier)?;
    let cold_start = started.elapsed();
    instantiate_and_check(&engine, &module, preopens, memory_mb)?;
    Ok(cold_start)
}

/// Shared instantiate-and-verify-`_start` tail for `load_check`/`load_check_gated` — factored out
/// so the two never drift on what "a clean load-check" actually proves.
fn instantiate_and_check(
    engine: &Engine,
    module: &Module,
    preopens: &[(String, String)],
    memory_mb: u64,
) -> Result<()> {
    let mut builder = WasiCtxBuilder::new();
    for (host, guest) in preopens {
        builder.preopened_dir(host, guest, DirPerms::READ, FilePerms::READ)?;
    }
    let wasi = builder.build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size((memory_mb.max(1) as usize) * 1024 * 1024)
        .build();
    let mut store = Store::new(engine, StoreState { wasi, limits });
    store.limiter(|s| &mut s.limits);
    let mut linker: Linker<StoreState> = Linker::new(engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi).context("link wasi")?;
    let instance = linker.instantiate(&mut store, module).context("instantiate")?;
    instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("module has no _start")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fuel budget generous enough that none of the pre-existing "must complete cleanly" tests
    /// below (napse/qsecbit/dnsxai/aegis-guard, cold-start measurements, the ADR 0016/0017 gated-
    /// load regression suite) come anywhere near exhausting it on their real, small, per-test
    /// inputs. Resource-budgets feature tests further down deliberately use a MUCH smaller budget
    /// to prove exhaustion; this one exists so every OTHER test keeps testing what it always
    /// tested, not incidentally the new fuel wall.
    const GENEROUS_TEST_FUEL: u64 = 50_000_000_000;

    fn built_wasm(id: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../target/wasm32-wasip1/release/{id}.wasm"))
    }

    /// The Step-1 proof: the ported `napse.wasm` LOADS, runs sandboxed (no host access beyond WASI),
    /// reads JSON flows from stdin, and writes an alert to stdout on a brute-force pattern.
    #[test]
    fn napse_wasm_loads_runs_sandboxed_and_detects() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: {} not built (cargo build -p napse --target wasm32-wasip1 --release)", wasm.display());
            return;
        }
        // 20 SSH SYN-only connections from one source = an SSH brute-force pattern.
        let mut input = String::new();
        for i in 0..20u64 {
            input.push_str(&format!(
                "{{\"type\":\"conn\",\"ts\":{}.0,\"src_ip\":\"203.0.113.7\",\"src_port\":{},\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}\n",
                1735000000 + i, 54000 + i
            ));
        }
        let out = run_wasi_module(&wasm, &[], input.into_bytes(), 256, Duration::from_secs(10), GENEROUS_TEST_FUEL)
            .expect("napse.wasm must load + run sandboxed under Wasmtime");
        let s = String::from_utf8_lossy(&out);
        eprintln!("napse.wasm sandboxed output ({} bytes): {s}", out.len());
        // Proof of execution = the Ok above. Bonus: NAPSE's own tested logic fired on the pattern.
        assert!(
            s.contains("rule_id") || s.contains("brute"),
            "expected a NAPSE alert on the brute-force pattern; got: {s:?}"
        );
    }

    /// Sandbox holds: a module with no `read` grant gets no preopens; it still runs on stdin alone.
    #[test]
    fn runs_with_no_grants() {
        let wasm = built_wasm("qsecbit");
        if !wasm.exists() { return; }
        // qsecbit scores every telemetry tick: cpu_norm,memory_norm,network_norm,disk_io_norm
        // (comma-separated floats — the REAL contract main.rs parses; see modules/qsecbit/src/main.rs).
        let input = b"0.01,0.20,0.01,0.05\n".to_vec();
        let out = run_wasi_module(&wasm, &[], input, 256, Duration::from_secs(5), GENEROUS_TEST_FUEL)
            .expect("qsecbit.wasm must run sandboxed");
        let s = String::from_utf8_lossy(&out);
        eprintln!("qsecbit sandboxed output: {s}");
        assert!(s.contains("\"score\""), "expected a qsecbit score line; got: {s:?}");
    }

    // =============================================================================================
    // Resource-budgets feature — the wasm CPU-metering wall (fuel), the second of the "two
    // resource walls" (memory/epoch being the first, pre-existing pair). Proves: (b) a tiny fuel
    // budget on a fuel-heavy input is a BOUNDED, ACCOUNTED failure (not a hang, not a silent
    // success), and a sane/default budget on the SAME input completes normally.
    // =============================================================================================

    /// A bigger brute-force pattern than the other napse tests use (100 connections, not 20) —
    /// more JSON parsing + heuristic-state work per run, so a genuinely tiny fuel budget can be
    /// exhausted partway through without needing an artificial infinite loop.
    fn fuel_heavy_napse_input() -> Vec<u8> {
        let mut input = String::new();
        for i in 0..100u64 {
            input.push_str(&format!(
                "{{\"type\":\"conn\",\"ts\":{}.0,\"src_ip\":\"203.0.113.7\",\"src_port\":{},\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}\n",
                1735000000 + i, 54000 + i
            ));
        }
        input.into_bytes()
    }

    /// **Proof (b), exhaustion half**: a TINY fuel budget on the fuel-heavy input is terminated —
    /// a clean, bounded, ACCOUNTED `Err` (the fuel-exhausted message), never a hang, never a
    /// silent wrong-output success, never a panic.
    #[test]
    fn fuel_budget_exhaustion_is_a_bounded_accounted_failure() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let began = std::time::Instant::now();
        // `timeout` (the epoch wall) is set generously ABOVE the "prompt" ceiling below so that,
        // even under heavy test-parallelism CPU contention (JIT-compiling napse.wasm concurrently
        // in sibling tests on a small core count), the epoch watchdog can never win the race and
        // mask what we're actually proving here: FUEL exhaustion, not the wall-clock wall.
        let result = run_wasi_module(&wasm, &[], fuel_heavy_napse_input(), 256, Duration::from_secs(60), 200);
        let elapsed = began.elapsed();
        eprintln!("fuel-exhaustion result: {result:?} after {elapsed:?}");
        let err = result.expect_err("a 200-unit fuel budget must NOT be enough to finish 100 connections' worth of JSON parsing + detection");
        let msg = format!("{err:#}");
        assert!(msg.contains("fuel budget exhausted"), "expected an explicit fuel-exhaustion message; got: {msg}");
        // Generous ceiling (NOT a tight perf assertion): fuel exhaustion is a deterministic,
        // instruction-count trap that fires in microseconds of actual wasm execution — the
        // measured wall-clock here is dominated by JIT-compiling napse.wasm (real CPU work, NOT
        // part of what fuel bounds), which itself gets slower under concurrent test-thread CPU
        // contention on a small core count. 45s comfortably distinguishes "bounded" from "hung
        // forever" without flaking under parallel `cargo test` load.
        assert!(elapsed < Duration::from_secs(45), "fuel exhaustion must be bounded, not a hang: {elapsed:?}");
    }

    /// **Proof (b), completion half**: the IDENTICAL fuel-heavy input under a sane (generous)
    /// budget completes normally, with napse's real detection output — the fuel wall bounds a
    /// runaway/malicious module without breaking a well-behaved one.
    #[test]
    fn fuel_budget_sane_default_completes_normally_on_the_same_fuel_heavy_input() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let out = run_wasi_module(&wasm, &[], fuel_heavy_napse_input(), 256, Duration::from_secs(10), GENEROUS_TEST_FUEL)
            .expect("a generous fuel budget must complete the same fuel-heavy input cleanly");
        let s = String::from_utf8_lossy(&out);
        eprintln!("fuel-budget (generous) output ({} bytes): {s}", out.len());
        assert!(
            s.contains("rule_id") || s.contains("brute"),
            "expected napse's real brute-force alert under a sane budget; got: {s:?}"
        );
    }

    /// The `resource_budget::Budget::effective_fuel` default (`WASM_DEFAULT_FUEL`, 2 billion) is
    /// itself "sane" for this repo's real modules — proves `--run-wasm`'s actual per-tick default
    /// (not just an inflated test constant) completes the fuel-heavy input too, so (d) "defaults
    /// apply when `resources` is absent" is proven all the way through the wasm engine, not just
    /// at the `Budget` struct level (see `hookprobe_manifest::resource_budget`'s own unit tests
    /// for the struct-level proof).
    #[test]
    fn wasm_default_fuel_budget_is_sane_for_a_real_module() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let default_fuel = hookprobe_manifest::types::Budget::default()
            .effective_fuel(&hookprobe_manifest::types::Runtime::Wasm);
        assert_eq!(default_fuel, hookprobe_manifest::resource_budget::WASM_DEFAULT_FUEL);
        let out = run_wasi_module(&wasm, &[], fuel_heavy_napse_input(), 256, Duration::from_secs(10), default_fuel)
            .expect("the real per-runtime default fuel budget must complete a real module's per-tick workload");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("rule_id") || s.contains("brute"), "got: {s:?}");
    }

    /// AOT round-trip: precompile napse.wasm, confirm `locate_executable` picks the `.cwasm` (bound
    /// via the sha256 sidecar), and confirm the resulting Module loads/instantiates/detects
    /// identically to the JIT (.wasm) path.
    #[test]
    fn precompile_roundtrip_binds_and_loads() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("hp-cwasm-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let report = precompile(&wasm, &tmp, "napse").expect("precompile must succeed");
        assert!(report.cwasm.exists(), ".cwasm must be written");
        assert!(report.cwasm_bytes > 0);
        eprintln!(
            "precompile: napse.wasm -> {} ({} bytes) in {:?}",
            report.cwasm.display(),
            report.cwasm_bytes,
            report.compile_elapsed
        );

        // Bind check passes against the real source wasm.
        assert!(cwasm_matches_source(&report.cwasm, &wasm), "sidecar must match source .wasm");

        // A tampered sidecar must be refused (never silently trusted).
        std::fs::write(sidecar_path(&report.cwasm), "0000").unwrap();
        assert!(!cwasm_matches_source(&report.cwasm, &wasm), "mismatched sidecar must be rejected");

        // Load-check via the Precompiled variant directly (bypassing locate_executable's path
        // search, which is a candidate-order test, not a load test).
        std::fs::write(sidecar_path(&report.cwasm), hex::encode(Sha256::digest(std::fs::read(&wasm).unwrap()))).unwrap();
        let exec = Executable::Precompiled { cwasm: report.cwasm.clone(), source_wasm: wasm.clone() };
        let cold_start = load_check(&exec, &[], 256).expect("precompiled module must load-check clean");
        eprintln!("cold-start via .cwasm (deserialize): {cold_start:?}");

        let src_exec = Executable::Source(wasm.clone());
        let jit_cold_start = load_check(&src_exec, &[], 256).expect("source module must load-check clean");
        eprintln!("cold-start via .wasm (JIT compile):  {jit_cold_start:?}");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Build a minimal `signature: required` `ModuleDef` for `id` whose sole declared artifact
    /// pins the SHA-256 of `wasm_bytes` — the shape `--write-artifact-digests` produces.
    fn required_def(id: &str, artifact_path: &str, wasm_bytes: &[u8]) -> ModuleDef {
        ModuleDef {
            id: id.to_string(),
            version: "1".to_string(),
            runtime: hookprobe_manifest::types::Runtime::Wasm,
            requires: Default::default(),
            provides: Default::default(),
            resources: None,
            signature: "required".to_string(),
            grants: Vec::new(),
            artifact: None,
            status: None,
            staging: None,
            artifacts: vec![hookprobe_manifest::module_def::ArtifactDigest {
                path: artifact_path.to_string(),
                role: hookprobe_manifest::module_def::ArtifactRole::Executable,
                arch: None,
                cpu: None,
                digest: hookprobe_manifest::module_def::Digest {
                    alg: "sha256".to_string(),
                    value: hex::encode(Sha256::digest(wasm_bytes)),
                },
            }],
            sig_verified: Some(true),
        }
    }

    /// **THE ADR 0016 CRITICAL-FINDING REGRESSION TEST.** Re-runs the exact attack the audit
    /// described: precompile the REAL napse.wasm, then swap the `.cwasm` on the writable cache
    /// for a DIFFERENT, validly-precompiled module (qsecbit — genuinely different, arbitrary
    /// "native" code, not just corrupted bytes), while leaving the sidecar claiming the (real,
    /// untouched) napse.wasm's hash — exactly what an attacker with only `/var` write access
    /// could do. Confirms:
    ///   1. the OLD sidecar-only check (`cwasm_matches_source`) is fooled (sanity — proves this
    ///      is a real reproduction of the finding, not a strawman),
    ///   2. `load_module_gated` (Fix A) NEVER executes the evil `.cwasm` — it falls back to
    ///      compiling the verified `.wasm` source, proven by actually RUNNING the loaded module
    ///      and observing napse's real detection behavior (not qsecbit's, which would trap on
    ///      NAPSE's JSON-lines input).
    #[test]
    fn cwasm_swap_attack_is_refused_by_the_gated_load_path() {
        let wasm = built_wasm("napse");
        let qsecbit_wasm = built_wasm("qsecbit");
        if !wasm.exists() || !qsecbit_wasm.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }

        let tmp = std::env::temp_dir().join(format!("hp-cwasm-attack-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // 1. Precompile the REAL napse.wasm -- what module.yaml's digest is (honestly) pinned to.
        let real_bytes = std::fs::read(&wasm).unwrap();
        let report = precompile(&wasm, &tmp, "napse").expect("precompile real napse.wasm");

        // 2. THE ATTACK: swap the .cwasm for a DIFFERENT, validly-precompiled module (stands in
        //    for arbitrary attacker-controlled native code — Wasmtime will happily deserialize
        //    it if asked, proving this isn't merely "malformed bytes get rejected").
        let attack_engine = Engine::new(&engine_config()).unwrap();
        let evil_wasm_bytes = std::fs::read(&qsecbit_wasm).unwrap();
        let evil_cwasm_bytes = attack_engine.precompile_module(&evil_wasm_bytes).unwrap();
        std::fs::write(&report.cwasm, &evil_cwasm_bytes).expect("swap in the evil .cwasm");
        // The sidecar is left EXACTLY as `precompile()` wrote it (sha256 of the real napse.wasm)
        // -- the attacker never touched the read-only-in-production .wasm, only the writable
        // .cwasm + (in a real deployment) its co-located sidecar file.

        // Sanity: the OLD check is fooled -- the sidecar still "matches" (the .wasm is untouched).
        assert!(
            cwasm_matches_source(&report.cwasm, &wasm),
            "sanity: the pre-Fix-A sidecar check is fooled by this attack (as the audit found)"
        );

        // 3. module.yaml pins the digest of the REAL bytes.
        let def = required_def("napse", "napse.wasm", &real_bytes);
        let install_dir = wasm.parent().unwrap();

        // `locate_executable`, run against the tampered cache, would pick the Precompiled variant
        // (the sidecar still matches) -- reproduce that resolution directly.
        let exec = Executable::Precompiled { cwasm: report.cwasm.clone(), source_wasm: wasm.clone() };

        // 4. THE FIX: `load_module_gated` must load the REAL napse.wasm bytes, NEVER the evil
        //    `.cwasm` -- `Module::deserialize_file` on `report.cwasm` must be unreachable here.
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, install_dir, None, None)
            .expect("gated load must succeed by falling back to the verified .wasm source");

        // Prove it by RUNNING the loaded module against NAPSE-shaped input: if the evil qsecbit
        // module had been loaded instead, this would trap (qsecbit expects comma-separated
        // floats on stdin, not JSON lines) rather than emit a NAPSE brute-force alert.
        let mut input = String::new();
        for i in 0..20u64 {
            input.push_str(&format!(
                "{{\"type\":\"conn\",\"ts\":{}.0,\"src_ip\":\"203.0.113.7\",\"src_port\":{},\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}\n",
                1735000000 + i, 54000 + i
            ));
        }
        let out = run_loaded_module(&engine, &module, &[], input.into_bytes(), 256, Duration::from_secs(10), GENEROUS_TEST_FUEL)
            .expect("the REAL napse module must run cleanly -- the evil swapped .cwasm never executed");
        let s = String::from_utf8_lossy(&out);
        eprintln!("cwasm-swap-attack regression test output: {s}");
        assert!(
            s.contains("rule_id") || s.contains("brute"),
            "expected the REAL napse.wasm's brute-force alert (proving the evil .cwasm never ran); got: {s:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Path-binding cross-check (Finding 3), exercised through the loader entry point: a
    /// `signature: required` module whose `artifacts:` only pins an unrelated file (not the real
    /// `.wasm` about to execute) must be REFUSED by `load_module_gated`, not silently loaded.
    #[test]
    fn load_module_gated_refuses_an_artifacts_block_that_does_not_bind_the_executable() {
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let real_bytes = std::fs::read(&wasm).unwrap();
        // Digest is declared for a DIFFERENT (non-existent) path -- never binds to napse.wasm.
        let mut def = required_def("napse", "napse.wasm", &real_bytes);
        def.artifacts[0].path = "unrelated-config.json".to_string();
        let install_dir = wasm.parent().unwrap();
        let exec = Executable::Source(wasm.clone());
        let engine = Engine::new(&engine_config()).unwrap();
        let err = load_module_gated(&engine, &exec, &def, install_dir, None, None).unwrap_err();
        eprintln!("path-binding refusal (expected): {err:#}");
    }

    /// **Fix A cold-start measurement**: compares the SAFE path (`load_module_gated` for a
    /// `signature: required` module — always JIT-compiles from verified bytes, never touches a
    /// `.cwasm`) against the OLD unauthenticated `.cwasm`-AOT fast path, for every module this
    /// repo actually ships. Reports real numbers so os-architect/verification-engineer can decide
    /// whether a device-sealed-AOT follow-up ADR is warranted (task requirement — not a pass/fail
    /// assertion beyond "both must load cleanly").
    #[test]
    fn fix_a_cold_start_regression_measurement() {
        for id in ["napse", "qsecbit", "dnsxai", "aegis-guard"] {
            let wasm = built_wasm(id);
            if !wasm.exists() {
                eprintln!("cold-start[{id}]: SKIP (not built)");
                continue;
            }
            let bytes = std::fs::read(&wasm).unwrap();
            let tmp = std::env::temp_dir().join(format!("hp-coldstart-{id}-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let report = precompile(&wasm, &tmp, id).expect("precompile");

            let def = required_def(id, &format!("{id}.wasm"), &bytes);
            let install_dir = wasm.parent().unwrap();

            // OLD path: trust the (here, legitimate) .cwasm via deserialize_file.
            let old_exec = Executable::Precompiled { cwasm: report.cwasm.clone(), source_wasm: wasm.clone() };
            let engine_old = Engine::new(&engine_config()).unwrap();
            let started = std::time::Instant::now();
            let _ = load_module(&engine_old, &old_exec).expect("old AOT path must still load");
            let old_cold_start = started.elapsed();

            // NEW (Fix A) path: always compiles from verified bytes for signature:required.
            let new_exec = Executable::Source(wasm.clone());
            let engine_new = Engine::new(&engine_config()).unwrap();
            let started = std::time::Instant::now();
            let _ = load_module_gated(&engine_new, &new_exec, &def, install_dir, None, None)
                .expect("gated (Fix A) path must load");
            let new_cold_start = started.elapsed();

            let delta = new_cold_start.saturating_sub(old_cold_start);
            eprintln!(
                "cold-start[{id}]: OLD(.cwasm deserialize)={old_cold_start:?}  NEW(Fix A, verified JIT)={new_cold_start:?}  delta={delta:?}"
            );
            let _ = std::fs::remove_dir_all(&tmp);
        }
    }

    // =============================================================================================
    // ADR 0017 regression tests — the authenticated AOT fast path, the version-drift fallback,
    // and the "no code path from a failed AOT check to executing the .cwasm" invariant.
    // =============================================================================================
    //
    // The AOT fallback counter is THREAD-LOCAL under `#[cfg(test)]` (see its definition above), so
    // each of these concurrently-scheduled tests observes only its own fallbacks — the before/after
    // and absolute-value assertions below are race-free by construction, no cross-test lock needed.

    /// Build a `signature: required` `ModuleDef` pinning BOTH the `.wasm` (role: executable) and
    /// an arch-qualified `.cwasm` (role: aot) — the shape `--write-artifact-digests` produces once
    /// `module.yaml` declares both entries (ADR 0017 D1).
    fn required_def_with_aot(
        id: &str,
        wasm_path: &str,
        wasm_bytes: &[u8],
        cwasm_path: &str,
        arch: &str,
        cwasm_bytes: &[u8],
    ) -> ModuleDef {
        let mut def = required_def(id, wasm_path, wasm_bytes);
        def.artifacts.push(hookprobe_manifest::module_def::ArtifactDigest {
            path: cwasm_path.to_string(),
            role: hookprobe_manifest::module_def::ArtifactRole::Aot,
            arch: Some(arch.to_string()),
            cpu: None,
            digest: hookprobe_manifest::module_def::Digest {
                alg: "sha256".to_string(),
                value: hex::encode(Sha256::digest(cwasm_bytes)),
            },
        });
        def
    }

    /// Run napse-shaped input through an already-loaded module and assert it produced NAPSE's real
    /// brute-force alert — the same "prove it by actually running it" discipline the Fix A swap
    /// test uses, so a passing assertion means the REAL napse code ran, not merely "something
    /// loaded without erroring".
    fn assert_runs_as_real_napse(engine: &Engine, module: &Module) {
        let mut input = String::new();
        for i in 0..20u64 {
            input.push_str(&format!(
                "{{\"type\":\"conn\",\"ts\":{}.0,\"src_ip\":\"203.0.113.7\",\"src_port\":{},\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}\n",
                1735000000 + i, 54000 + i
            ));
        }
        let out = run_loaded_module(engine, module, &[], input.into_bytes(), 256, Duration::from_secs(10), GENEROUS_TEST_FUEL)
            .expect("the loaded module must run cleanly");
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.contains("rule_id") || s.contains("brute"),
            "expected NAPSE's real brute-force alert; got: {s:?}"
        );
    }

    /// **Proof 1 — the authenticated AOT fast path is used.** Precompile the REAL napse.wasm into
    /// the module's own install dir (standing in for the RO rootfs `/usr/lib/hookprobe/modules/
    /// napse/` layout), declare its digest under `role: aot` for `module_sig::running_arch()`, and
    /// confirm `load_module_gated` (a) records ZERO ADR 0017 fallbacks (proving it took the fast
    /// path, not the JIT floor) and (b) actually runs as real napse.
    #[test]
    fn adr0017_aot_fast_path_is_used_for_a_verified_rootfs_cwasm() {
        reset_aot_fallback_count_for_test();
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let real_bytes = std::fs::read(&wasm).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0017-fastpath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&wasm, install_dir.join("napse.wasm")).unwrap();

        // Precompile with the EXACT engine config every load uses (`engine_config()`) so this is a
        // genuinely deserialize-compatible blob, native to this test process's own arch.
        let engine_for_precompile = Engine::new(&engine_config()).unwrap();
        let cwasm_bytes = engine_for_precompile.precompile_module(&real_bytes).unwrap();
        std::fs::write(install_dir.join("napse.cwasm"), &cwasm_bytes).unwrap();

        let arch = module_sig::running_arch();
        let def = required_def_with_aot("napse", "napse.wasm", &real_bytes, "napse.cwasm", arch, &cwasm_bytes);
        let exec = Executable::Source(install_dir.join("napse.wasm"));

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, None, None)
            .expect("the verified AOT blob must deserialize cleanly");
        let after = aot_fallback_count();
        assert_eq!(after, before, "a clean, verified, arch-matching AOT blob must record ZERO fallbacks");

        assert_runs_as_real_napse(&engine, &module);
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    // =============================================================================================
    // ADR 0021 — per-CPU-microarch AOT tier SELECTION. These prove `load_module_gated` picks the
    // `.a76.cwasm` when the manifest CPU tier is `cortex-a76` AND its signed digest verifies, and
    // FAILS CLOSED to the A72-safe baseline (never a JIT crash) on a missing/tampered A76 blob.
    // Blobs are made distinguishable BY BEHAVIOR (baseline = real napse, A76 stand-in = real
    // qsecbit) purely so the test can observe WHICH tier ran — the loader treats them identically.
    // =============================================================================================

    /// A `signature: required` napse module declaring BOTH arm64 AOT tiers: a baseline
    /// (`napse.cwasm`, no `cpu`) and an A76 (`napse.a76.cwasm`, `cpu: cortex-a76`), each digest-
    /// pinned to the bytes it is handed. `arch` is this test process's own running arch so the
    /// entries actually apply.
    fn required_def_two_aot_tiers(
        arch: &str,
        wasm_bytes: &[u8],
        baseline_cwasm: &[u8],
        a76_cwasm: &[u8],
    ) -> ModuleDef {
        use hookprobe_manifest::module_def::{ArtifactDigest, ArtifactRole, Digest};
        let mut def = required_def("napse", "napse.wasm", wasm_bytes);
        def.artifacts.push(ArtifactDigest {
            path: "napse.cwasm".to_string(),
            role: ArtifactRole::Aot,
            arch: Some(arch.to_string()),
            cpu: None, // baseline (A72-safe)
            digest: Digest { alg: "sha256".to_string(), value: hex::encode(Sha256::digest(baseline_cwasm)) },
        });
        def.artifacts.push(ArtifactDigest {
            path: "napse.a76.cwasm".to_string(),
            role: ArtifactRole::Aot,
            arch: Some(arch.to_string()),
            cpu: Some("cortex-a76".to_string()),
            digest: Digest { alg: "sha256".to_string(), value: hex::encode(Sha256::digest(a76_cwasm)) },
        });
        def
    }

    fn assert_runs_as_real_qsecbit(engine: &Engine, module: &Module) {
        // qsecbit's contract: comma-separated telemetry floats in → a `"score"` line out. napse
        // would produce nothing useful on this input — so a `"score"` line PROVES the qsecbit blob
        // (the A76 stand-in) is what deserialized and ran.
        let out = run_loaded_module(engine, module, &[], b"0.01,0.20,0.01,0.05\n".to_vec(), 256, Duration::from_secs(10), GENEROUS_TEST_FUEL)
            .expect("the loaded module must run cleanly");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("\"score\""), "expected qsecbit's score output (proves the A76 blob ran); got: {s:?}");
    }

    /// **A76-1 — the A76 tier is SELECTED when the manifest says A76.** Two valid AOT blobs on disk;
    /// with `cpu_tier = Some("cortex-a76")` the loader deserializes+runs the `.a76.cwasm` (qsecbit
    /// stand-in), NOT the baseline (napse) — ZERO fallbacks.
    #[test]
    fn adr0021_a76_tier_selects_and_verifies_the_a76_blob() {
        reset_aot_fallback_count_for_test();
        let napse = built_wasm("napse");
        let qsecbit = built_wasm("qsecbit");
        if !napse.exists() || !qsecbit.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }
        let napse_bytes = std::fs::read(&napse).unwrap();
        let qsecbit_bytes = std::fs::read(&qsecbit).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0021-a76-select-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&napse, install_dir.join("napse.wasm")).unwrap();

        let eng = Engine::new(&engine_config()).unwrap();
        let baseline_cwasm = eng.precompile_module(&napse_bytes).unwrap();     // baseline = napse
        let a76_cwasm = eng.precompile_module(&qsecbit_bytes).unwrap();        // A76 stand-in = qsecbit
        std::fs::write(install_dir.join("napse.cwasm"), &baseline_cwasm).unwrap();
        std::fs::write(install_dir.join("napse.a76.cwasm"), &a76_cwasm).unwrap();

        let arch = module_sig::running_arch();
        let def = required_def_two_aot_tiers(arch, &napse_bytes, &baseline_cwasm, &a76_cwasm);
        let exec = Executable::Source(install_dir.join("napse.wasm"));

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, None, Some("cortex-a76"))
            .expect("the verified A76 blob must deserialize cleanly");
        assert_eq!(aot_fallback_count(), before, "A76 tier selected + verified → ZERO fallbacks");
        assert_runs_as_real_qsecbit(&engine, &module); // proves the .a76 file ran, not the baseline
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **A76-2 — a baseline (A72) manifest uses the BASELINE blob, never the A76 one.** Same two
    /// blobs on disk; with `cpu_tier = None` the loader runs the baseline (napse), NEVER touching
    /// the A76 blob — ZERO fallbacks.
    #[test]
    fn adr0021_baseline_tier_uses_baseline_blob_never_the_a76_one() {
        reset_aot_fallback_count_for_test();
        let napse = built_wasm("napse");
        let qsecbit = built_wasm("qsecbit");
        if !napse.exists() || !qsecbit.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }
        let napse_bytes = std::fs::read(&napse).unwrap();
        let qsecbit_bytes = std::fs::read(&qsecbit).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0021-baseline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&napse, install_dir.join("napse.wasm")).unwrap();

        let eng = Engine::new(&engine_config()).unwrap();
        let baseline_cwasm = eng.precompile_module(&napse_bytes).unwrap();
        let a76_cwasm = eng.precompile_module(&qsecbit_bytes).unwrap();
        std::fs::write(install_dir.join("napse.cwasm"), &baseline_cwasm).unwrap();
        std::fs::write(install_dir.join("napse.a76.cwasm"), &a76_cwasm).unwrap();

        let arch = module_sig::running_arch();
        let def = required_def_two_aot_tiers(arch, &napse_bytes, &baseline_cwasm, &a76_cwasm);
        let exec = Executable::Source(install_dir.join("napse.wasm"));

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, None, None) // A72 baseline
            .expect("the verified baseline blob must deserialize cleanly");
        assert_eq!(aot_fallback_count(), before, "baseline tier selected + verified → ZERO fallbacks");
        assert_runs_as_real_napse(&engine, &module); // baseline (napse) ran, NOT the A76 (qsecbit) blob
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **A76-3 — MISSING A76 blob fails closed to the baseline (never a crash).** The manifest says
    /// A76 but only the baseline `.cwasm` is on disk. The loader must NOT crash trying to load a
    /// non-existent A76 blob — it falls back to the verified baseline (napse), ZERO fallbacks (the
    /// baseline AOT itself succeeded).
    #[test]
    fn adr0021_missing_a76_blob_falls_back_to_baseline_fail_closed() {
        reset_aot_fallback_count_for_test();
        let napse = built_wasm("napse");
        let qsecbit = built_wasm("qsecbit");
        if !napse.exists() || !qsecbit.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }
        let napse_bytes = std::fs::read(&napse).unwrap();
        let qsecbit_bytes = std::fs::read(&qsecbit).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0021-missing-a76-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&napse, install_dir.join("napse.wasm")).unwrap();

        let eng = Engine::new(&engine_config()).unwrap();
        let baseline_cwasm = eng.precompile_module(&napse_bytes).unwrap();
        let a76_cwasm = eng.precompile_module(&qsecbit_bytes).unwrap(); // pinned in def, but NOT written to disk
        std::fs::write(install_dir.join("napse.cwasm"), &baseline_cwasm).unwrap();
        // deliberately DO NOT write napse.a76.cwasm

        let arch = module_sig::running_arch();
        let def = required_def_two_aot_tiers(arch, &napse_bytes, &baseline_cwasm, &a76_cwasm);
        let exec = Executable::Source(install_dir.join("napse.wasm"));

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, None, Some("cortex-a76"))
            .expect("a missing A76 blob must fall back to the baseline, never crash");
        assert_eq!(aot_fallback_count(), before, "the baseline AOT succeeded → no JIT fallback recorded");
        assert_runs_as_real_napse(&engine, &module); // the baseline blob ran
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **A76-4 — a TAMPERED A76 blob fails closed to the baseline + emits ArtifactTamper.** The
    /// manifest says A76; the `.a76.cwasm` on disk is a valid-but-WRONG blob (digest mismatch vs the
    /// signed A76 entry). The loader must refuse it (tamper event), never deserialize it, and fall
    /// back to the verified baseline (napse) — no crash.
    #[test]
    fn adr0021_tampered_a76_blob_falls_back_to_baseline_and_emits_tamper() {
        reset_aot_fallback_count_for_test();
        let napse = built_wasm("napse");
        let qsecbit = built_wasm("qsecbit");
        if !napse.exists() || !qsecbit.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }
        let napse_bytes = std::fs::read(&napse).unwrap();
        let qsecbit_bytes = std::fs::read(&qsecbit).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0021-tamper-a76-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&napse, install_dir.join("napse.wasm")).unwrap();

        let eng = Engine::new(&engine_config()).unwrap();
        let baseline_cwasm = eng.precompile_module(&napse_bytes).unwrap();
        // The SIGNED A76 entry pins qsecbit's bytes, but the FILE on disk is a different valid blob
        // (napse's) — a digest mismatch = tamper.
        let signed_a76 = eng.precompile_module(&qsecbit_bytes).unwrap();
        let on_disk_a76 = baseline_cwasm.clone(); // wrong bytes for the A76 entry
        std::fs::write(install_dir.join("napse.cwasm"), &baseline_cwasm).unwrap();
        std::fs::write(install_dir.join("napse.a76.cwasm"), &on_disk_a76).unwrap();

        let arch = module_sig::running_arch();
        let def = required_def_two_aot_tiers(arch, &napse_bytes, &baseline_cwasm, &signed_a76);
        let exec = Executable::Source(install_dir.join("napse.wasm"));
        let events = install_dir.join("events");

        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, Some(&events), Some("cortex-a76"))
            .expect("a tampered A76 blob must fall back to the verified baseline, never crash");
        // The baseline blob ran (napse), NOT the tampered A76.
        assert_runs_as_real_napse(&engine, &module);
        let contents = std::fs::read_to_string(&events).expect("ArtifactTamper event must be appended for the A76 mismatch");
        assert!(contents.contains("supply_chain_tamper"), "got: {contents}");
        assert!(contents.contains("napse.a76.cwasm"), "the tamper event must name the A76 blob: {contents}");
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **Proof 2 — the bypass stays closed.** Corrupt/replace the RO-rootfs `.cwasm` (swap in a
    /// DIFFERENT, validly-precompiled module — qsecbit — so a naive "does it deserialize" check
    /// would wrongly pass) while the SIGNED digest still pins the REAL napse `.cwasm`'s bytes.
    /// Confirms: it does NOT execute the bad blob (proven by running it — real napse output, never
    /// qsecbit), falls back to verified `from_binary` JIT, increments the ADR 0017 fallback
    /// counter, and emits `ArtifactTamper`.
    #[test]
    fn adr0017_tampered_rootfs_cwasm_never_executes_falls_back_to_verified_jit() {
        reset_aot_fallback_count_for_test();
        let wasm = built_wasm("napse");
        let qsecbit_wasm = built_wasm("qsecbit");
        if !wasm.exists() || !qsecbit_wasm.exists() {
            eprintln!("SKIP: napse.wasm and/or qsecbit.wasm not built");
            return;
        }
        let real_bytes = std::fs::read(&wasm).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0017-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&wasm, install_dir.join("napse.wasm")).unwrap();

        let engine_for_precompile = Engine::new(&engine_config()).unwrap();
        let real_cwasm_bytes = engine_for_precompile.precompile_module(&real_bytes).unwrap();

        // THE ATTACK: the file ON DISK is qsecbit's (genuinely different, validly-precompiled)
        // native code -- but module.yaml's digest still pins the REAL napse .cwasm's bytes.
        let qsecbit_bytes = std::fs::read(&qsecbit_wasm).unwrap();
        let evil_cwasm_bytes = engine_for_precompile.precompile_module(&qsecbit_bytes).unwrap();
        std::fs::write(install_dir.join("napse.cwasm"), &evil_cwasm_bytes).unwrap();

        let arch = module_sig::running_arch();
        let def = required_def_with_aot("napse", "napse.wasm", &real_bytes, "napse.cwasm", arch, &real_cwasm_bytes);
        let exec = Executable::Source(install_dir.join("napse.wasm"));
        let events = install_dir.join("events");

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, Some(&events), None)
            .expect("must fall back to the verified .wasm JIT floor, never error out");
        let after = aot_fallback_count();
        assert!(after > before, "a digest-mismatched AOT blob must record at least one fallback");

        // Prove the evil qsecbit .cwasm never ran: qsecbit expects comma-separated floats on
        // stdin, not JSON lines -- it would trap on NAPSE-shaped input.
        assert_runs_as_real_napse(&engine, &module);

        let contents = std::fs::read_to_string(&events).expect("ArtifactTamper event must be appended");
        assert!(contents.contains("supply_chain_tamper"), "got: {contents}");
        assert!(contents.contains("napse.cwasm"), "got: {contents}");

        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **Proof 3 — version/config-drift fallback.** Precompile with a Wasmtime `Config` that
    /// deliberately does NOT match `engine_config()` (the one every load uses) — simulating the
    /// exact "embedded Wasmtime drift" scenario the ADR's Blocker describes: the DIGEST is
    /// legitimately correct (these really are the pinned bytes, no tamper), but
    /// `Module::deserialize` refuses them because the config/version baked into the `.cwasm`
    /// header is incompatible. Confirms: JIT fallback, counter increment, and — critically — NO
    /// `ArtifactTamper` event (this is drift, not tampering) while still never executing the
    /// undeserializable blob.
    #[test]
    fn adr0017_version_config_drift_deserialize_error_falls_back_to_verified_jit() {
        reset_aot_fallback_count_for_test();
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let real_bytes = std::fs::read(&wasm).unwrap();
        let install_dir = std::env::temp_dir().join(format!("hp-adr0017-drift-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&wasm, install_dir.join("napse.wasm")).unwrap();

        // A DIFFERENT config than `engine_config()` uses (epoch_interruption OFF instead of ON) —
        // Wasmtime bakes config compatibility into the .cwasm header, so deserializing this under
        // the real `engine_config()` engine must fail, even though the bytes are exactly what was
        // (honestly) pinned.
        let mut drift_config = Config::new();
        drift_config.epoch_interruption(false);
        let drift_engine = Engine::new(&drift_config).unwrap();
        let drifted_cwasm_bytes = drift_engine.precompile_module(&real_bytes).unwrap();
        std::fs::write(install_dir.join("napse.cwasm"), &drifted_cwasm_bytes).unwrap();

        let arch = module_sig::running_arch();
        // The digest pins the ACTUAL (drifted) bytes on disk -- no tamper, purely a version/config
        // mismatch, exactly the scenario this test proves falls back safely.
        let def = required_def_with_aot("napse", "napse.wasm", &real_bytes, "napse.cwasm", arch, &drifted_cwasm_bytes);
        let exec = Executable::Source(install_dir.join("napse.wasm"));
        let events = install_dir.join("events");

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, Some(&events), None)
            .expect("must fall back to the verified .wasm JIT floor on a deserialize Err");
        let after = aot_fallback_count();
        assert!(after > before, "a deserialize-incompatible (drifted) AOT blob must record a fallback");

        assert_runs_as_real_napse(&engine, &module);

        // Drift is NOT tampering -- the digest genuinely matched -- so no ArtifactTamper event.
        if events.exists() {
            let contents = std::fs::read_to_string(&events).unwrap();
            assert!(!contents.contains("supply_chain_tamper"), "drift must not read as tamper: {contents}");
        }
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **Proof 4 — the writable `/var`-style cache is never consulted for a signed module.** Even
    /// when `exec` (as `locate_executable` would resolve it) points at a bogus "cache" path that
    /// would error loudly if ever opened, `load_module_gated` for a `signature: required` module
    /// must never touch it: it always falls back to the verified `.wasm` (no RO-rootfs `.cwasm`
    /// exists in this test's install dir), runs as real napse, and records exactly the one expected
    /// ADR 0017 fallback (reason: absent AOT), never erroring on the bogus cache path.
    #[test]
    fn adr0017_var_style_cache_cwasm_is_never_consulted_for_a_signed_module() {
        reset_aot_fallback_count_for_test();
        let wasm = built_wasm("napse");
        if !wasm.exists() {
            eprintln!("SKIP: napse.wasm not built");
            return;
        }
        let real_bytes = std::fs::read(&wasm).unwrap();
        let def = required_def("napse", "napse.wasm", &real_bytes);
        // A FRESH, isolated install dir (never the shared dev-workspace target/ tree, which other
        // tests/manual runs may have left a stray napse.cwasm in) — no co-located napse.cwasm
        // exists here, so `locate_rootfs_aot` must return None.
        let install_dir = std::env::temp_dir().join(format!("hp-adr0017-novarcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&install_dir);
        std::fs::create_dir_all(&install_dir).unwrap();
        std::fs::copy(&wasm, install_dir.join("napse.wasm")).unwrap();

        // A "/var cache"-style path that is INVALID to even open as a file (a directory) --
        // proof-by-explosion: if load_module_gated ever tried `fs::read` on this for a signed
        // module, the test would fail with an unexpected error instead of succeeding.
        let fake_cache = std::env::temp_dir().join(format!("hp-fake-var-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fake_cache);
        std::fs::create_dir_all(&fake_cache).unwrap();
        let exec = Executable::Precompiled { cwasm: fake_cache.clone(), source_wasm: install_dir.join("napse.wasm") };

        let before = aot_fallback_count();
        let engine = Engine::new(&engine_config()).unwrap();
        let module = load_module_gated(&engine, &exec, &def, &install_dir, None, None)
            .expect("must compile the verified .wasm; the bogus cache path must never be opened");
        let after = aot_fallback_count();
        assert_eq!(after, before + 1, "no RO-rootfs aot present -> exactly one fallback recorded");

        assert_runs_as_real_napse(&engine, &module);
        let _ = std::fs::remove_dir_all(&fake_cache);
        let _ = std::fs::remove_dir_all(&install_dir);
    }

    /// **ADR 0017 cold-start measurement**: for every module this repo ships (napse, qsecbit,
    /// dnsxai, aegis-guard), compares the AUTHENTICATED AOT fast path (`load_module_gated` with a
    /// verified RO-rootfs `.cwasm` present) against the ADR 0016 Fix A JIT floor (no `.cwasm`
    /// present at all) — both through the IDENTICAL gated load path production uses, so this is
    /// the real, restored number, not a hypothetical. Reports real numbers (task requirement, not
    /// a pass/fail assertion beyond "both must load cleanly and zero fallbacks on the AOT run").
    #[test]
    fn adr0017_cold_start_measurement_vs_fix_a_baseline() {
        for id in ["napse", "qsecbit", "dnsxai", "aegis-guard"] {
            let wasm = built_wasm(id);
            if !wasm.exists() {
                eprintln!("cold-start[{id}]: SKIP (not built)");
                continue;
            }
            let real_bytes = std::fs::read(&wasm).unwrap();
            let install_dir = std::env::temp_dir().join(format!("hp-adr0017-coldstart-{id}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&install_dir);
            std::fs::create_dir_all(&install_dir).unwrap();
            std::fs::copy(&wasm, install_dir.join(format!("{id}.wasm"))).unwrap();

            // --- JIT floor: no .cwasm present at all -> load_module_gated must compile fresh. ---
            let jit_def = required_def(id, &format!("{id}.wasm"), &real_bytes);
            let jit_exec = Executable::Source(install_dir.join(format!("{id}.wasm")));
            let engine_jit = Engine::new(&engine_config()).unwrap();
            let started = std::time::Instant::now();
            let _ = load_module_gated(&engine_jit, &jit_exec, &jit_def, &install_dir, None, None)
                .expect("Fix A floor must load");
            let jit_cold_start = started.elapsed();

            // --- ADR 0017 fast path: a verified, arch-matching RO-rootfs .cwasm IS present. ---
            let engine_for_precompile = Engine::new(&engine_config()).unwrap();
            let cwasm_bytes = engine_for_precompile.precompile_module(&real_bytes).unwrap();
            std::fs::write(install_dir.join(format!("{id}.cwasm")), &cwasm_bytes).unwrap();
            let arch = module_sig::running_arch();
            let aot_def = required_def_with_aot(
                id, &format!("{id}.wasm"), &real_bytes, &format!("{id}.cwasm"), arch, &cwasm_bytes,
            );
            let aot_exec = Executable::Source(install_dir.join(format!("{id}.wasm")));
            reset_aot_fallback_count_for_test();
            let engine_aot = Engine::new(&engine_config()).unwrap();
            let started = std::time::Instant::now();
            let _ = load_module_gated(&engine_aot, &aot_exec, &aot_def, &install_dir, None, None)
                .expect("ADR 0017 verified AOT fast path must load");
            let aot_cold_start = started.elapsed();
            assert_eq!(aot_fallback_count(), 0, "{id}: a clean verified AOT blob must record zero fallbacks");

            eprintln!(
                "ADR0017 cold-start[{id}]: JIT-floor(Fix A, verified .wasm compile)={jit_cold_start:?}  \
                 AOT-fast-path(ADR 0017, verified .cwasm deserialize)={aot_cold_start:?}  \
                 speedup={:.1}x",
                jit_cold_start.as_secs_f64() / aot_cold_start.as_secs_f64().max(1e-9)
            );
            let _ = std::fs::remove_dir_all(&install_dir);
        }
    }

    /// Epoch machinery: a runaway module (infinite loop, no host calls) must be TRAPPED by the
    /// epoch deadline callback + ticker, not left to hang the process. This is the same
    /// interruption pattern `run_wasi_module_streaming` uses in production, exercised directly
    /// against a minimal inline-WAT module so the test needs no extra build step.
    #[test]
    fn epoch_interruption_traps_a_runaway_loop() {
        let engine = Engine::new(&engine_config()).expect("engine");
        // A WASI command export that never returns and makes no host calls.
        let wat = r#"(module (memory (export "memory") 1) (func (export "_start") (loop $l (br $l))))"#;
        let module = Module::new(&engine, wat).expect("valid inline WAT");

        let wasi = WasiCtxBuilder::new().build_p1();
        let limits = StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).build();
        let mut store = Store::new(&engine, StoreState { wasi, limits });
        store.limiter(|s| &mut s.limits);
        // `engine_config()` now always enables `consume_fuel` (resource-budgets feature) — set an
        // effectively-unbounded fuel budget so THIS test keeps proving epoch interruption catches
        // a wedged module, not incidentally the (separate, deliberately tested elsewhere) fuel
        // wall tripping first on an unfueled Store.
        store.set_fuel(u64::MAX).expect("set_fuel");

        // Force-interrupt: the kill-switch is set from the start, proving the callback path traps
        // the module rather than letting Continue(1) spin forever.
        let kill = Arc::new(AtomicBool::new(true));
        let kill_cb = kill.clone();
        store.epoch_deadline_callback(move |_| {
            if kill_cb.load(Ordering::Relaxed) {
                anyhow::bail!("kill-switch");
            }
            Ok(UpdateDeadline::Continue(1))
        });
        store.set_epoch_deadline(1);

        let engine_wd = engine.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(5));
            engine_wd.increment_epoch();
        });

        let mut linker: Linker<StoreState> = Linker::new(&engine);
        preview1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi).unwrap();
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start").unwrap();

        let began = std::time::Instant::now();
        let result = start.call(&mut store, ());
        let elapsed = began.elapsed();
        eprintln!("epoch interruption result: {result:?} after {elapsed:?}");
        assert!(result.is_err(), "epoch machinery must trap the runaway loop, not hang");
        assert!(elapsed < Duration::from_secs(5), "interruption must be prompt, not a hang: {elapsed:?}");
    }
}
