//! XDP / BPF capability derivation — "detect once, query forever". Bootstrap probes each NIC's
//! driver name (a stable fact, already in `ScanInterface.driver`) and the kernel release; this maps
//! them to (a) whether the NIC supports NATIVE (driver-hook) XDP and (b) whether the host kernel can
//! run our stateful BPF (the `bpf_ct_lookup` fast-path, kernel ≥ 5.19). Read by [`crate::inspect`]'s
//! mode ladder (ADR 0005): native-XDP NICs get `xdp-native`, everything else gets `tc-bpf` (still
//! fully in-kernel), and a pre-5.19 kernel drops to the userspace software floor.
//!
//! The allowlist is the practical thing: names not on it use TC-bpf, so being conservative here only
//! costs the (small) native-vs-clsact delta — never correctness. Wi-Fi (mac80211/brcmfmac/ath*) is
//! intentionally ABSENT: no Wi-Fi driver has native XDP.

/// Drivers with upstream NATIVE (driver-hook) XDP. Source: the xdp-project driver matrix + kernel
/// driver support (2024-2026). NOTE the deliberate absences: `bcmgenet` (the Pi's Ethernet — no
/// native XDP), `r8169`/`e1000e` (common cheap NICs — no native XDP), and all Wi-Fi. Those fall to
/// TC-bpf, which is exactly right.
const NATIVE_XDP_DRIVERS: &[&str] = &[
    // Intel
    "igb", "igc", "ixgbe", "ixgbevf", "i40e", "iavf", "ice", "fm10k",
    // Mellanox / NVIDIA
    "mlx4_en", "mlx5_core",
    // Broadcom NIC (NOT bcmgenet)
    "bnxt_en",
    // Marvell
    "mvneta", "mvpp2", "octeontx2_nicpf", "octeontx2_nicvf",
    // Synopsys DWMAC / stmmac core — RK3588 & many ARM SoCs; native XDP upstream since ~5.13. The
    // driver name varies by platform glue, so list the known variants (exact match — a false
    // positive would make the loader attach native XDP to a NIC that can't, and fail).
    "stmmac", "stmmaceth", "st_gmac", "dwmac", "dwmac-rk", "dwmac-sun8i", "rk_gmac", "rk_gmac-dwmac",
    // Virtual / cloud
    "virtio_net", "veth", "tun",
    // Others with native XDP
    "nfp", "qede", "sfc", "nicvf", "thunder-nicvf", "ena", "gve", "tsnep",
];

/// Does this driver support native (driver-hook) XDP? Unknown/absent ⇒ false ⇒ TC-bpf fallback.
pub fn driver_supports_native_xdp(driver: &str) -> bool {
    let d = driver.trim();
    !d.is_empty() && NATIVE_XDP_DRIVERS.iter().any(|&k| k.eq_ignore_ascii_case(d))
}

/// The host kernel can run our stateful BPF (SCHED_CLS + `bpf_{skb,xdp}_ct_lookup`) iff it is
/// ≥ 5.19 — the release where the conntrack-lookup kfuncs merged (ADR 0005). BTF availability is a
/// separate load-time concern handled by the loader (ship a BTFGen blob for BSP kernels lacking it).
pub fn kernel_bpf_stateful(osrelease: &str) -> bool {
    let (maj, min) = parse_kver(osrelease);
    maj > 5 || (maj == 5 && min >= 19)
}

/// Parse the leading `MAJOR.MINOR` out of a uname release like `6.1.0-49-arm64` or `5.19.0`.
fn parse_kver(osrelease: &str) -> (u32, u32) {
    let mut it = osrelease.split(['.', '-', '+']);
    let maj = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (maj, min)
}

// ---------------------------------------------------------------------------
// CO-RE BTF source resolution — the "ship a BTFGen blob for BSP kernels lacking
// it" seam this file's `kernel_bpf_stateful` doc comment promised.
//
// Debian/Ubuntu (and our own arm64-UEFI/virt) kernels are built with
// `CONFIG_DEBUG_INFO_BTF=y`, so `/sys/kernel/btf/vmlinux` exists at runtime and
// libbpf resolves CO-RE relocations against it with zero help. The Raspberry Pi
// Foundation's `6.12.93+rpt-rpi-v8` (Pi4/CM4) and `6.12.93+rpt-rpi-2712`
// (Pi5/CM5) kernels — which the unified fat-boot image (ADR 0029/0030) boots on
// Pi metal — do NOT enable that option, so that path is ABSENT and every CO-RE
// loader (`libbpf: kernel BTF is missing ... -ESRCH`) crash-loops.
//
// Fix: the build host runs `pahole -J --btf_encode_detached` on the matching
// `-dbg` package's debug vmlinux and stages a detached BTF blob into the rootfs
// at `<BTF_STAGE_DIR>/vmlinux-<uname -r>.btf`; the loader points libbpf's
// `btf_custom_path` at it. This module holds only the PURE path-selection
// decision (unit-tested below); the libbpf `open_opts` wiring lives in each
// module's `bpf.rs` behind `--features bpf`.
// ---------------------------------------------------------------------------

/// The kernel's native BTF, present iff the running kernel has `CONFIG_DEBUG_INFO_BTF=y`.
pub const NATIVE_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// Where `builder/mkosi-arm64/make-pi-image.sh` stages per-kernel detached BTF blobs, named by
/// `uname -r` so the loader can pick the one matching the booted kernel.
pub const BTF_STAGE_DIR: &str = "/usr/lib/hookprobe/btf";

/// The absolute path a shipped blob would live at for a given `uname -r` release string.
pub fn shipped_btf_path(uname_release: &str) -> String {
    format!("{BTF_STAGE_DIR}/vmlinux-{}.btf", uname_release.trim())
}

/// The resolved BTF source a CO-RE loader should use before `.load()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfSource {
    /// The kernel exposes native BTF at [`NATIVE_BTF_PATH`]; do nothing — libbpf finds it itself.
    /// This is the normal case (Debian/Ubuntu/UEFI kernels) and MUST stay a no-op so the amd64/
    /// virt path is byte-for-byte unchanged.
    KernelNative,
    /// No native BTF, but a shipped blob exists at this path (RPi BSP kernels). The loader sets
    /// `open_opts.btf_custom_path` to it so CO-RE relocations resolve against it.
    Custom(String),
}

/// PURE path-selection decision (unit-tested). `native_present` is whether [`NATIVE_BTF_PATH`]
/// exists; `blob_exists` probes whether the candidate shipped blob exists. Returns:
///   - `Ok(KernelNative)` when the kernel has native BTF (do nothing),
///   - `Ok(Custom(path))` when native is absent but a shipped blob is present,
///   - `Err(_)` when BOTH are absent — an HONEST hard failure: a CO-RE enforcement loader that
///     cannot resolve BTF cannot load, and must say so rather than silently no-op.
pub fn resolve_btf_source(
    native_present: bool,
    uname_release: &str,
    blob_exists: impl Fn(&str) -> bool,
) -> Result<BtfSource, String> {
    if native_present {
        return Ok(BtfSource::KernelNative);
    }
    let blob = shipped_btf_path(uname_release);
    if blob_exists(&blob) {
        Ok(BtfSource::Custom(blob))
    } else {
        Err(format!(
            "kernel BTF missing: {NATIVE_BTF_PATH} absent (kernel lacks CONFIG_DEBUG_INFO_BTF) and \
             no shipped blob at {blob} for kernel '{}'. CO-RE relocations cannot resolve — this \
             loader cannot attach. Rebuild the image so make-pi-image.sh stages a BTF blob for \
             this kernel (base/drivers/SOURCES.md).",
            uname_release.trim()
        ))
    }
}

/// Runtime convenience: read `uname -r` from `/proc/sys/kernel/osrelease` and probe the real
/// filesystem, then apply [`resolve_btf_source`]. Loaders call this; the `bpf.rs` glue turns a
/// `Custom(path)` into `open_opts.btf_custom_path`. Kept dependency-free (no libc) — the release
/// string comes from procfs.
pub fn resolve_btf_source_live() -> Result<BtfSource, String> {
    let uname = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| format!("read /proc/sys/kernel/osrelease: {e}"))?;
    let native_present = std::path::Path::new(NATIVE_BTF_PATH).exists();
    resolve_btf_source(native_present, uname.trim(), |p| std::path::Path::new(p).exists())
}

/// The ONE shared libbpf-wiring helper both napse CO-RE loaders call (napse-quarantine,
/// napse-l2guard — and any future CO-RE loader) instead of copy-pasting the `open_opts` poke.
/// Call it on a fresh [`libbpf_rs::ObjectBuilder`] BEFORE `open_file()`:
///
/// ```ignore
/// let mut builder = ObjectBuilder::default();
/// let _btf_guard = hookprobe_manifest::xdp::apply_btf_custom_path(&mut builder)?; // keep alive!
/// let obj = builder.open_file(obj_path)?.load()?;
/// ```
///
/// On a Debian/UEFI kernel (native BTF present) this is a no-op and returns `Ok(None)`. On an RPi
/// BSP kernel it resolves the shipped blob, points `bpf_object_open_opts.btf_custom_path` at it,
/// and returns `Ok(Some(guard))`. If NEITHER native BTF nor a shipped blob is present it returns
/// `Err` — the caller MUST propagate it (fail-closed on load, honest); a CO-RE enforcement loader
/// that can't resolve BTF cannot attach and must not silently pretend otherwise.
///
/// libbpf-rs 0.24 exposes no safe `btf_custom_path` setter, so this writes the field through the
/// public [`libbpf_rs::AsRawLibbpf`] pointer. The returned `CString` OWNS the storage that pointer
/// references — the caller MUST keep it alive until after `open_file()`/`load()` (its buffer is
/// read there). Moving the guard is safe (a `CString`'s heap buffer is address-stable); dropping it
/// before `load()` is NOT — hence the explicit `_btf_guard` binding in every call site.
#[cfg(feature = "bpf")]
pub fn apply_btf_custom_path(
    builder: &mut libbpf_rs::ObjectBuilder,
) -> Result<Option<std::ffi::CString>, String> {
    use libbpf_rs::AsRawLibbpf;
    match resolve_btf_source_live()? {
        BtfSource::KernelNative => Ok(None),
        BtfSource::Custom(path) => {
            let c = std::ffi::CString::new(path.as_str())
                .map_err(|e| format!("shipped BTF path {path} has an interior NUL: {e}"))?;
            // SAFETY: `as_libbpf_object()` returns a pointer to `builder`'s own `opts`, valid for as
            // long as `builder` lives (which outlives the `open_file()` the caller runs right after
            // this). We set `btf_custom_path` to `c`'s heap buffer; `c` is returned to the caller,
            // which keeps it alive past `load()`. libbpf copies/dups the path string during
            // `bpf_object__open_file`, so the pointer only needs to be valid across that call.
            unsafe {
                let opts = builder.as_libbpf_object().as_ptr();
                (*opts).btf_custom_path = c.as_ptr();
            }
            eprintln!(
                "hookprobe: no native kernel BTF ({NATIVE_BTF_PATH} absent) — resolving CO-RE \
                 relocations against shipped blob {path}"
            );
            Ok(Some(c))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_xdp_allowlist() {
        // fleet NICs that DO have native XDP
        assert!(driver_supports_native_xdp("igc")); // N100 (Intel 2.5G)
        assert!(driver_supports_native_xdp("stmmac")); // RK3588 Ethernet
        assert!(driver_supports_native_xdp("virtio_net")); // cloud
        assert!(driver_supports_native_xdp("mlx5_core"));
        // the ones that must fall to TC-bpf
        assert!(!driver_supports_native_xdp("bcmgenet")); // Pi Ethernet — no native XDP
        assert!(!driver_supports_native_xdp("brcmfmac")); // Pi Wi-Fi — no native XDP
        assert!(!driver_supports_native_xdp("r8169")); // cheap Realtek — no native XDP
        assert!(!driver_supports_native_xdp("e1000e"));
        assert!(!driver_supports_native_xdp("")); // unknown ⇒ false
    }

    #[test]
    fn kernel_version_gate() {
        assert!(kernel_bpf_stateful("6.1.0-49-arm64")); // our image
        assert!(kernel_bpf_stateful("6.6.0")); // Pi5
        assert!(kernel_bpf_stateful("5.19.0")); // the exact floor
        assert!(!kernel_bpf_stateful("5.18.0")); // one below — no ct-lookup kfuncs
        assert!(!kernel_bpf_stateful("5.10.110-rockchip")); // older BSP
        assert!(!kernel_bpf_stateful("")); // unknown ⇒ conservative false → software floor
    }

    #[test]
    fn btf_blob_path_is_named_by_uname() {
        // The blob name MUST match `uname -r` verbatim so the loader picks the right kernel's blob
        // out of the two the fat-boot image ships.
        assert_eq!(
            shipped_btf_path("6.12.93+rpt-rpi-v8"),
            "/usr/lib/hookprobe/btf/vmlinux-6.12.93+rpt-rpi-v8.btf"
        );
        assert_eq!(
            shipped_btf_path("6.12.93+rpt-rpi-2712"),
            "/usr/lib/hookprobe/btf/vmlinux-6.12.93+rpt-rpi-2712.btf"
        );
        // trailing whitespace (procfs osrelease has a newline) is trimmed.
        assert_eq!(shipped_btf_path("6.12.93+rpt-rpi-v8\n"), shipped_btf_path("6.12.93+rpt-rpi-v8"));
    }

    #[test]
    fn btf_native_present_is_noop() {
        // Debian/UEFI/amd64: native BTF present ⇒ KernelNative, regardless of any blob. This is the
        // guard that the normal (non-Pi) path is untouched.
        let r = resolve_btf_source(true, "6.1.0-49-arm64", |_| false).unwrap();
        assert_eq!(r, BtfSource::KernelNative);
        // even if a blob also happened to exist, native wins (never override a real kernel BTF).
        let r = resolve_btf_source(true, "6.12.93+rpt-rpi-v8", |_| true).unwrap();
        assert_eq!(r, BtfSource::KernelNative);
    }

    #[test]
    fn btf_custom_blob_selected_when_native_absent() {
        // RPi BSP kernel: no native BTF, shipped blob present ⇒ Custom(that path).
        let r = resolve_btf_source(false, "6.12.93+rpt-rpi-2712", |p| {
            p == "/usr/lib/hookprobe/btf/vmlinux-6.12.93+rpt-rpi-2712.btf"
        })
        .unwrap();
        assert_eq!(
            r,
            BtfSource::Custom("/usr/lib/hookprobe/btf/vmlinux-6.12.93+rpt-rpi-2712.btf".into())
        );
    }

    #[test]
    fn btf_hard_error_when_neither_present() {
        // No native BTF AND no shipped blob ⇒ honest hard error (never a silent no-op — a security
        // enforcement loader that cannot load MUST say so).
        let e = resolve_btf_source(false, "6.12.93+rpt-rpi-v8", |_| false).unwrap_err();
        assert!(e.contains("kernel BTF missing"), "msg: {e}");
        assert!(e.contains("6.12.93+rpt-rpi-v8"), "msg names the kernel: {e}");
    }
}
