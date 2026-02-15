/**
 * NAPSE Syscall Monitor - Targeted Syscall Tracing
 *
 * Monitors specific syscalls for suspicious patterns:
 * - openat: /etc/shadow, /etc/passwd reads
 * - connect: connections to known C2 ports
 * - write: cron/systemd persistence attempts
 *
 * Uses a verdict map (kill_list) so userspace can flag PIDs
 * for immediate termination on next syscall.
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#include <uapi/linux/bpf.h>
#include <linux/sched.h>

/* Configuration */
#define MONITOR_TABLE_SIZE   16384
#define RINGBUF_SIZE         (1 << 20)  /* 1MB */
#define COMM_SIZE            16
#define PATH_SIZE            128

/* Syscall event types */
#define SYSCALL_OPENAT       0x01
#define SYSCALL_CONNECT      0x02
#define SYSCALL_WRITE        0x03

/* Severity levels */
#define SEV_INFO             0
#define SEV_LOW              1
#define SEV_MEDIUM           2
#define SEV_HIGH             3
#define SEV_CRITICAL         4

/* Statistics */
enum {
    SM_STAT_TOTAL = 0,
    SM_STAT_FLAGGED = 1,
    SM_STAT_KILLED = 2,
    SM_STAT_EXPORTS = 3,
};

/* Syscall event for ring buffer (64 bytes) */
struct syscall_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  syscall_type;
    __u8  severity;
    __u16 dst_port;           /* For connect events */
    __u32 dst_ip;             /* For connect events */
    char  comm[COMM_SIZE];    /* 16 bytes */
    char  path[24];           /* Truncated path for openat/write */
};

/* Per-PID monitoring state */
struct pid_monitor {
    __u32 pid;
    __u32 uid;
    __u32 open_count;         /* shadow/passwd opens */
    __u32 connect_count;      /* suspicious connects */
    __u32 write_count;        /* persistence writes */
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

/* Known C2 ports (commonly used by malware) */
#define C2_PORT_4444  4444   /* Metasploit default */
#define C2_PORT_5555  5555   /* Common RAT */
#define C2_PORT_8888  8888   /* Common RAT */
#define C2_PORT_1337  1337   /* Leet port */

/* eBPF Maps */
BPF_HASH(pid_monitors, __u32, struct pid_monitor, MONITOR_TABLE_SIZE);
BPF_HASH(sc_kill_list, __u32, __u8, 4096);
BPF_ARRAY(sc_stats, __u64, 4);
BPF_RINGBUF_OUTPUT(syscall_events, RINGBUF_SIZE);

static __always_inline void sm_inc_stat(__u32 idx) {
    __u64 *val = sc_stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/* Check if port is a known C2 port */
static __always_inline int is_c2_port(__u16 port) {
    switch (port) {
        case C2_PORT_4444:
        case C2_PORT_5555:
        case C2_PORT_8888:
        case C2_PORT_1337:
            return 1;
        default:
            return 0;
    }
}

/*
 * Tracepoint: syscalls/sys_enter_openat
 *
 * Monitors file opens for sensitive paths.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    sm_inc_stat(SM_STAT_TOTAL);

    /* Check kill list first */
    __u8 *should_kill = sc_kill_list.lookup(&pid);
    if (should_kill && *should_kill == 1) {
        bpf_send_signal(9);
        sm_inc_stat(SM_STAT_KILLED);
        return 0;
    }

    /* Read the filename argument */
    char path[PATH_SIZE] = {};
    const char *filename = (const char *)args->filename;
    bpf_probe_read_user_str(&path, sizeof(path), filename);

    /* Check for sensitive file access */
    __u8 severity = SEV_INFO;

    /* /etc/shadow access */
    if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' &&
        path[4] == '/' && path[5] == 's' && path[6] == 'h' && path[7] == 'a') {
        severity = SEV_HIGH;
    }
    /* /etc/passwd access (informational) */
    else if (path[0] == '/' && path[1] == 'e' && path[2] == 't' && path[3] == 'c' &&
             path[4] == '/' && path[5] == 'p' && path[6] == 'a' && path[7] == 's') {
        severity = SEV_LOW;
    }
    /* /proc/kcore, /proc/kallsyms (kernel memory access) */
    else if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' && path[3] == 'o' &&
             path[4] == 'c' && path[5] == '/' && path[6] == 'k') {
        severity = SEV_MEDIUM;
    }

    if (severity > SEV_INFO) {
        sm_inc_stat(SM_STAT_FLAGGED);

        /* Update per-PID monitor */
        struct pid_monitor *mon = pid_monitors.lookup(&pid);
        if (mon) {
            mon->open_count += 1;
            mon->last_seen_ns = now;
        } else {
            struct pid_monitor new_mon = {};
            new_mon.pid = pid;
            new_mon.uid = uid;
            new_mon.open_count = 1;
            new_mon.first_seen_ns = now;
            new_mon.last_seen_ns = now;
            pid_monitors.update(&pid, &new_mon);
        }

        /* Export event */
        struct syscall_event *evt = syscall_events.ringbuf_output(sizeof(*evt), 0);
        if (evt) {
            evt->timestamp_ns = now;
            evt->pid = pid;
            evt->uid = uid;
            evt->syscall_type = SYSCALL_OPENAT;
            evt->severity = severity;
            evt->dst_port = 0;
            evt->dst_ip = 0;
            bpf_get_current_comm(&evt->comm, COMM_SIZE);
            __builtin_memcpy(evt->path, path, 24);
            syscall_events.ringbuf_submit(evt, 0);
            sm_inc_stat(SM_STAT_EXPORTS);
        }
    }

    return 0;
}

/*
 * Tracepoint: syscalls/sys_enter_connect
 *
 * Monitors outbound connections for C2 port patterns.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    sm_inc_stat(SM_STAT_TOTAL);

    /* Check kill list */
    __u8 *should_kill = sc_kill_list.lookup(&pid);
    if (should_kill && *should_kill == 1) {
        bpf_send_signal(9);
        sm_inc_stat(SM_STAT_KILLED);
        return 0;
    }

    /* Read sockaddr to get port and IP */
    struct sockaddr_in addr = {};
    bpf_probe_read_user(&addr, sizeof(addr), (void *)args->uservaddr);

    /* Only check AF_INET (IPv4) */
    if (addr.sin_family != 2)  /* AF_INET = 2 */
        return 0;

    __u16 dst_port = __constant_ntohs(addr.sin_port);
    __u32 dst_ip = addr.sin_addr.s_addr;

    if (is_c2_port(dst_port)) {
        sm_inc_stat(SM_STAT_FLAGGED);

        struct pid_monitor *mon = pid_monitors.lookup(&pid);
        if (mon) {
            mon->connect_count += 1;
            mon->last_seen_ns = now;
        } else {
            struct pid_monitor new_mon = {};
            new_mon.pid = pid;
            new_mon.uid = uid;
            new_mon.connect_count = 1;
            new_mon.first_seen_ns = now;
            new_mon.last_seen_ns = now;
            pid_monitors.update(&pid, &new_mon);
        }

        struct syscall_event *evt = syscall_events.ringbuf_output(sizeof(*evt), 0);
        if (evt) {
            evt->timestamp_ns = now;
            evt->pid = pid;
            evt->uid = uid;
            evt->syscall_type = SYSCALL_CONNECT;
            evt->severity = SEV_HIGH;
            evt->dst_port = dst_port;
            evt->dst_ip = dst_ip;
            bpf_get_current_comm(&evt->comm, COMM_SIZE);
            evt->path[0] = '\0';
            syscall_events.ringbuf_submit(evt, 0);
            sm_inc_stat(SM_STAT_EXPORTS);
        }
    }

    return 0;
}

/*
 * Tracepoint: syscalls/sys_enter_write
 *
 * Monitors writes to persistence paths (cron, systemd, rc.local).
 * NOTE: We can only check the fd number here; the HealingEngine
 * correlates fd→path via /proc/<pid>/fd/<fd> in userspace.
 * This tracepoint primarily serves as a trigger; detailed analysis
 * is done by the Python HealingEngine.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Check kill list */
    __u8 *should_kill = sc_kill_list.lookup(&pid);
    if (should_kill && *should_kill == 1) {
        bpf_send_signal(9);
        sm_inc_stat(SM_STAT_KILLED);
    }

    /* Write tracing is handled in userspace via /proc correlation.
       The kill_list check above is the primary eBPF-side enforcement. */
    return 0;
}
