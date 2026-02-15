/**
 * NAPSE Hotpatch - Runtime Vulnerability Mitigation
 *
 * Intercepts vulnerable syscall patterns and returns EPERM without
 * modifying the kernel. Patch rules are loaded from userspace via
 * a BPF map.
 *
 * Use cases:
 * - Block specific argument patterns to vulnerable syscalls
 * - Prevent exploitation of known CVEs before kernel patches
 * - Temporary mitigations during maintenance windows
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#include <uapi/linux/bpf.h>
#include <linux/sched.h>

/* Configuration */
#define PATCH_TABLE_SIZE     256
#define RINGBUF_SIZE         (1 << 18)  /* 256KB */
#define COMM_SIZE            16

/* Patch rule types */
#define PATCH_BLOCK_SYSCALL  0x01   /* Block entire syscall for comm */
#define PATCH_BLOCK_ARG      0x02   /* Block if arg matches pattern */
#define PATCH_LOG_ONLY       0x03   /* Log but don't block */

/* Statistics */
enum {
    HP_STAT_CHECKED = 0,
    HP_STAT_BLOCKED = 1,
    HP_STAT_LOGGED = 2,
    HP_STAT_EXPORTS = 3,
};

/* Patch rule loaded from userspace */
struct patch_rule {
    __u32 syscall_nr;             /* Target syscall number */
    __u8  patch_type;             /* PATCH_BLOCK_SYSCALL, etc. */
    __u8  enabled;                /* 1 = active, 0 = disabled */
    __u8  pad[2];
    char  target_comm[COMM_SIZE]; /* Only apply to this comm ("" = all) */
    __u64 block_count;            /* How many times this rule fired */
};

/* Hotpatch event for ring buffer (32 bytes) */
struct hotpatch_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 syscall_nr;
    __u8  patch_type;
    __u8  blocked;               /* 1 if blocked, 0 if logged only */
    __u8  pad[2];
    char  comm[COMM_SIZE - 4];   /* Truncated to fit 32 bytes */
};

/* eBPF Maps */
BPF_HASH(patch_table, __u32, struct patch_rule, PATCH_TABLE_SIZE);
BPF_ARRAY(hp_stats, __u64, 4);
BPF_RINGBUF_OUTPUT(hotpatch_events, RINGBUF_SIZE);

static __always_inline void hp_inc_stat(__u32 idx) {
    __u64 *val = hp_stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/* Check if two comm strings match (or rule comm is empty = match all) */
static __always_inline int comm_matches(const char *rule_comm, const char *proc_comm) {
    /* Empty rule comm matches all processes */
    if (rule_comm[0] == '\0')
        return 1;

    /* Simple prefix comparison */
    #pragma unroll
    for (int i = 0; i < COMM_SIZE; i++) {
        if (rule_comm[i] == '\0')
            return 1;  /* End of rule = match */
        if (rule_comm[i] != proc_comm[i])
            return 0;  /* Mismatch */
    }
    return 1;
}

/*
 * Raw tracepoint: sys_enter
 *
 * Called on every syscall entry. Checks the patch_table for matching
 * rules and either blocks (returns -EPERM via bpf_override_return)
 * or logs the event.
 *
 * NOTE: bpf_override_return requires CONFIG_BPF_KPROBE_OVERRIDE=y
 * in the kernel config. This is available on most modern distros.
 *
 * In BCC, this is attached via:
 *   b.attach_raw_tracepoint(tp="sys_enter", fn_name="hotpatch_sys_enter")
 */
RAW_TRACEPOINT_PROBE(sys_enter) {
    /* args: struct pt_regs *regs, long id */
    __u32 syscall_nr = ((__u64)ctx->args[1]) & 0xFFFFFFFF;

    hp_inc_stat(HP_STAT_CHECKED);

    /* Look up patch rule for this syscall */
    struct patch_rule *rule = patch_table.lookup(&syscall_nr);
    if (!rule || !rule->enabled)
        return 0;  /* No rule or disabled */

    /* Check comm filter */
    char comm[COMM_SIZE] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    if (!comm_matches(rule->target_comm, comm))
        return 0;  /* Not the target process */

    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 blocked = 0;

    if (rule->patch_type == PATCH_BLOCK_SYSCALL) {
        /* Block the syscall by overriding return value */
        bpf_override_return(ctx, -1);  /* -EPERM */
        hp_inc_stat(HP_STAT_BLOCKED);
        blocked = 1;
        __sync_fetch_and_add(&rule->block_count, 1);
    } else if (rule->patch_type == PATCH_LOG_ONLY) {
        hp_inc_stat(HP_STAT_LOGGED);
    }

    /* Export event */
    struct hotpatch_event *evt = hotpatch_events.ringbuf_output(sizeof(*evt), 0);
    if (evt) {
        evt->timestamp_ns = now;
        evt->pid = pid;
        evt->syscall_nr = syscall_nr;
        evt->patch_type = rule->patch_type;
        evt->blocked = blocked;
        __builtin_memcpy(evt->comm, comm, COMM_SIZE - 4);
        hotpatch_events.ringbuf_submit(evt, 0);
        hp_inc_stat(HP_STAT_EXPORTS);
    }

    return 0;
}
