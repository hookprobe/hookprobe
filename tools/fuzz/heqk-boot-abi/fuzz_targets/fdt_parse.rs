#![no_main]
// ADR 0061 D1 / ADR 0062 T0: the bounded DTB reader HBoot runs on the firmware-supplied blob. A hostile or corrupt
// DTB must be refused cleanly. Invariants: never panics; every reported count fits its fixed table; a truncated
// table is flagged rather than silently dropped; on success, the struct walk ended on FDT_END.
use boot_abi::fdt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(inv) = fdt::parse(data) {
        assert!(inv.nmem <= fdt::MAX_MEM && inv.nresv <= fdt::MAX_RESV && inv.ncpus <= fdt::MAX_CPUS);
        assert!(inv.resv_nomap <= inv.nresv);
        assert!(inv.mem[..inv.nmem].iter().all(|r| r.size != 0));
        let _ = inv.mem_total();
    }
});
