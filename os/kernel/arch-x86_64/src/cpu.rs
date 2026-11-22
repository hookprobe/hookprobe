// SPDX-License-Identifier: AGPL-3.0-only
//! GDT + TSS, IDT + exception/IRQ handlers, SYSCALL MSRs, and the ring-3 (EL0-equivalent) enter/resume path.
//!
//! GDT layout (also what STAR encodes):
//!   0x00 null · 0x08 kernel code64 · 0x10 kernel data · 0x18 user data (DPL3) · 0x20 user code64 (DPL3) · 0x28 TSS
//! STAR[47:32] = 0x08 (SYSCALL: CS 0x08, SS 0x10); STAR[63:48] = 0x10 (SYSRET: SS 0x18|3, CS 0x20|3).

use crate::io::{qemu_exit, rdmsr, wrmsr, EXIT_FAIL};
use crate::kprintln;
use core::arch::{asm, naked_asm};
use core::sync::atomic::{AtomicU64, Ordering};

pub const KCODE: u16 = 0x08;
pub const KDATA: u16 = 0x10;
pub const UDATA: u16 = 0x18;
pub const UCODE: u16 = 0x20;
pub const TSS_SEL: u16 = 0x28;

#[repr(C, packed)]
struct Tss {
    _r0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    _r1: u64,
    ist: [u64; 7],
    _r2: u64,
    _r3: u16,
    iomap: u16,
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);

/// Kernel stack used on any CPL3 → CPL0 interrupt (TSS.rsp0) and for #DF (IST1).
static mut RING0_STACK: Stack = Stack([0; 16384]);
static mut DF_STACK: Stack = Stack([0; 16384]);

static mut TSS: Tss = Tss { _r0: 0, rsp0: 0, rsp1: 0, rsp2: 0, _r1: 0, ist: [0; 7], _r2: 0, _r3: 0, iomap: 104 };

#[repr(C, align(16))]
struct Gdt([u64; 7]);
static mut GDT: Gdt = Gdt([
    0,
    0x00AF_9A00_0000_FFFF, // kernel code64: P, DPL0, L
    0x00CF_9200_0000_FFFF, // kernel data
    0x00CF_F200_0000_FFFF, // user data: DPL3
    0x00AF_FA00_0000_FFFF, // user code64: DPL3, L
    0,                     // TSS low  (filled at runtime)
    0,                     // TSS high
]);

#[repr(C, packed)]
struct Dtr {
    limit: u16,
    base: u64,
}

pub fn load_gdt_tss() {
    unsafe {
        let tss = &raw mut TSS;
        (*tss).rsp0 = (&raw const RING0_STACK as u64) + 16384;
        (*tss).ist[0] = (&raw const DF_STACK as u64) + 16384;
        let base = tss as u64;
        let limit = (core::mem::size_of::<Tss>() - 1) as u64;
        let low = (limit & 0xFFFF)
            | ((base & 0xFF_FFFF) << 16)
            | (0x89u64 << 40) // present, 64-bit TSS (available)
            | (((limit >> 16) & 0xF) << 48)
            | (((base >> 24) & 0xFF) << 56);
        let gdt = &raw mut GDT;
        (*gdt).0[5] = low;
        (*gdt).0[6] = base >> 32;
        let dtr = Dtr { limit: (core::mem::size_of::<Gdt>() - 1) as u16, base: gdt as u64 };
        asm!(
            "lgdt [{d}]",
            "push {kc}",
            "lea {t}, [rip + 2f]",
            "push {t}",
            "retfq",
            "2:",
            "mov ds, {kd:x}",
            "mov es, {kd:x}",
            "mov ss, {kd:x}",
            "xor {t:e}, {t:e}",
            "mov fs, {t:x}",
            "mov gs, {t:x}",
            "ltr {ts:x}",
            d = in(reg) &dtr,
            kc = const KCODE as u64,
            kd = in(reg) KDATA as u64,
            ts = in(reg) TSS_SEL as u64,
            t = out(reg) _,
        );
    }
}

// ---------------------------------------------------------------- IDT

#[repr(C)]
#[derive(Clone, Copy)]
struct Gate {
    off_lo: u16,
    sel: u16,
    ist: u8,
    attr: u8,
    off_mid: u16,
    off_hi: u32,
    _z: u32,
}

#[repr(C, align(16))]
struct Idt([Gate; 256]);
static mut IDT: Idt = Idt([Gate { off_lo: 0, sel: 0, ist: 0, attr: 0, off_mid: 0, off_hi: 0, _z: 0 }; 256]);

fn set_gate(v: usize, h: u64, ist: u8) {
    unsafe {
        (*(&raw mut IDT)).0[v] = Gate {
            off_lo: h as u16,
            sel: KCODE,
            ist,
            attr: 0x8E, // present, DPL0, 64-bit interrupt gate
            off_mid: (h >> 16) as u16,
            off_hi: (h >> 32) as u32,
            _z: 0,
        };
    }
}

#[repr(C)]
pub struct Frame {
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
}

pub static BP_HITS: AtomicU64 = AtomicU64::new(0);
pub static TICKS: AtomicU64 = AtomicU64::new(0);
pub static UFAULT_ADDR: AtomicU64 = AtomicU64::new(0);
pub static UFAULT_CODE: AtomicU64 = AtomicU64::new(0);

fn fatal(what: &str, f: &Frame, code: u64) -> ! {
    kprintln!("[X1] FAIL — {} at rip={:#x} cs={:#x} code={:#x}", what, f.ip, f.cs, code);
    qemu_exit(EXIT_FAIL)
}

extern "x86-interrupt" fn h_de(f: Frame) {
    fatal("#DE", &f, 0)
}
extern "x86-interrupt" fn h_bp(_f: Frame) {
    BP_HITS.fetch_add(1, Ordering::SeqCst);
}
extern "x86-interrupt" fn h_ud(f: Frame) {
    fatal("#UD", &f, 0)
}
extern "x86-interrupt" fn h_df(f: Frame, code: u64) -> ! {
    fatal("#DF", &f, code)
}
extern "x86-interrupt" fn h_gp(f: Frame, code: u64) {
    fatal("#GP", &f, code)
}
extern "x86-interrupt" fn h_pf(f: Frame, code: u64) {
    let cr2: u64;
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags)) };
    if code & 4 != 0 && f.cs & 3 == 3 {
        // A CPL3 access the page tables refused: the isolation we want. Abandon the user context.
        UFAULT_ADDR.store(cr2, Ordering::SeqCst);
        UFAULT_CODE.store(code, Ordering::SeqCst);
        unsafe { resume_kernel(RESUME_USER_FAULT) }
    }
    kprintln!("[X1] FAIL — kernel #PF cr2={:#x}", cr2);
    fatal("#PF", &f, code)
}
extern "x86-interrupt" fn h_other(f: Frame) {
    fatal("unexpected exception", &f, 0)
}
extern "x86-interrupt" fn h_other_code(f: Frame, code: u64) {
    fatal("unexpected exception (with error code)", &f, code)
}
extern "x86-interrupt" fn h_timer(_f: Frame) {
    TICKS.fetch_add(1, Ordering::SeqCst);
    crate::apic::eoi();
}
extern "x86-interrupt" fn h_spurious(_f: Frame) {}

pub const TIMER_VECTOR: u8 = 0x20;
pub const SPURIOUS_VECTOR: u8 = 0xFF;

pub fn load_idt() {
    // Vectors that push an error code: 8, 10-14, 17, 21, 29, 30.
    for v in 0..32usize {
        let with_code = matches!(v, 8 | 10..=14 | 17 | 21 | 29 | 30);
        let h = if with_code { h_other_code as *const () as usize } else { h_other as *const () as usize };
        set_gate(v, h as u64, 0);
    }
    set_gate(0, h_de as *const () as u64, 0);
    set_gate(3, h_bp as *const () as u64, 0);
    set_gate(6, h_ud as *const () as u64, 0);
    set_gate(8, h_df as *const () as u64, 1); // IST1: a #DF never runs on a possibly-broken stack
    set_gate(13, h_gp as *const () as u64, 0);
    set_gate(14, h_pf as *const () as u64, 0);
    set_gate(TIMER_VECTOR as usize, h_timer as *const () as u64, 0);
    set_gate(SPURIOUS_VECTOR as usize, h_spurious as *const () as u64, 0);
    let dtr = Dtr { limit: (core::mem::size_of::<Idt>() - 1) as u16, base: &raw const IDT as u64 };
    unsafe { asm!("lidt [{}]", in(reg) &dtr, options(nostack, preserves_flags)) };
}

// ---------------------------------------------------------------- SYSCALL + ring 3

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

pub const RESUME_USER_FAULT: u64 = 0xFA17_0000_0000_0000;

pub fn enable_syscall() {
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | 1); // SCE
    wrmsr(IA32_STAR, ((KDATA as u64) << 48) | ((KCODE as u64) << 32));
    wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);
    wrmsr(IA32_FMASK, 0x4_0700); // clear AC, IF, DF, TF on entry
}

/// Kernel RSP saved by `enter_user`; `resume_kernel` returns through it.
static mut X1_KERNEL_RSP: u64 = 0;

/// Run user code at CPL3 from `entry` with stack `user_rsp` (IF=0). Returns when the user context ends:
/// via SYSCALL (returns the user's RAX) or a user page fault (returns RESUME_USER_FAULT).
#[unsafe(naked)]
pub unsafe extern "sysv64" fn enter_user(entry: u64, user_rsp: u64) -> u64 {
    naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rip + {krsp}], rsp",
        "push {uds}",  // SS
        "push rsi",    // RSP
        "push 0x2",    // RFLAGS: IF=0, IOPL=0
        "push {ucs}",  // CS
        "push rdi",    // RIP
        "iretq",
        uds = const (UDATA | 3) as u64,
        ucs = const (UCODE | 3) as u64,
        krsp = sym X1_KERNEL_RSP,
    )
}

/// Abandon the current (user or interrupt) context and return `code` from `enter_user`.
#[unsafe(naked)]
pub unsafe extern "sysv64" fn resume_kernel(code: u64) -> ! {
    naked_asm!(
        "mov dx, {kd}",
        "mov ss, dx",
        "mov rax, rdi",
        "mov rsp, [rip + {krsp}]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
        kd = const KDATA,
        krsp = sym X1_KERNEL_RSP,
    )
}

/// SYSCALL lands here at CPL0 with the USER stack still in RSP: never touch it, just hand RAX back.
#[unsafe(naked)]
unsafe extern "sysv64" fn syscall_entry() {
    naked_asm!("mov rdi, rax", "jmp {r}", r = sym resume_kernel)
}
