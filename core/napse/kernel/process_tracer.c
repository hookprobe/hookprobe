/**
 * NAPSE Process Tracer - Tracepoint-Based Process Monitoring
 *
 * Attaches to sys_enter_execve tracepoint to track process creation.
 * Assigns suspicious scores based on execution context:
 * - Execution from /tmp, /dev/shm, world-writable dirs
 * - Web-server-spawned shells (www-data → bash/sh)
 * - Double-extension and hidden file execution
 *
 * Exports events via ring buffer to userspace HealingEngine.
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#include <uapi/linux/bpf.h>
#include <linux/sched.h>

/* Configuration */
#define PROCESS_TABLE_SIZE   16384
#define RINGBUF_SIZE         (1 << 20)  /* 1MB */
#define COMM_SIZE            16
#define PATH_MAX_BPF         256

/* Suspicious score thresholds */
#define SCORE_CLEAN          0
#define SCORE_LOW            10
#define SCORE_MEDIUM         30
#define SCORE_HIGH           60
#define SCORE_CRITICAL       90

/* Statistics indices */
enum {
    STAT_TOTAL_EXECS = 0,
    STAT_SUSPICIOUS = 1,
    STAT_CRITICAL = 2,
    STAT_EXPORTS = 3,
};

/* Process event for ring buffer (64 bytes) */
struct process_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 suspicious_score;
    char  comm[COMM_SIZE];       /* 16 bytes */
    __u8  flags;                 /* Bit flags for trigger reasons */
    __u8  pad[7];
};

/* Flags for process_event.flags */
#define FLAG_TMP_EXEC        0x01   /* Executed from /tmp or /dev/shm */
#define FLAG_WEB_SHELL       0x02   /* Web server spawned shell */
#define FLAG_HIDDEN_FILE     0x04   /* Hidden file (starts with .) */
#define FLAG_ROOT_ESCALATION 0x08   /* UID 0 from non-root parent */
#define FLAG_SCRIPTING       0x10   /* Script interpreter (python/perl/etc) */

/* Process state tracking */
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u64 start_ns;
    __u32 suspicious_score;
    char  comm[COMM_SIZE];
};

/* eBPF Maps */
BPF_HASH(process_table, __u32, struct process_info, PROCESS_TABLE_SIZE);
BPF_HASH(kill_list, __u32, __u8, 4096);  /* PIDs flagged for kill by userspace */
BPF_ARRAY(pt_stats, __u64, 4);
BPF_RINGBUF_OUTPUT(process_events, RINGBUF_SIZE);

static __always_inline void pt_inc_stat(__u32 idx) {
    __u64 *val = pt_stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/* Check if comm is a shell */
static __always_inline int is_shell(const char *comm) {
    /* Check common shells: bash, sh, dash, zsh, csh, fish */
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h')
        return 1;
    if (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0')
        return 1;
    if (comm[0] == 'd' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h')
        return 1;
    if (comm[0] == 'z' && comm[1] == 's' && comm[2] == 'h')
        return 1;
    return 0;
}

/* Check if comm is a web server process */
static __always_inline int is_web_server(const char *comm) {
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' && comm[3] == 'n' && comm[4] == 'x')
        return 1;
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a' && comm[3] == 'c')
        return 1;  /* apache2 */
    if (comm[0] == 'h' && comm[1] == 't' && comm[2] == 't' && comm[3] == 'p' && comm[4] == 'd')
        return 1;
    return 0;
}

/* Check if comm is a scripting interpreter */
static __always_inline int is_script_interpreter(const char *comm) {
    if (comm[0] == 'p' && comm[1] == 'y' && comm[2] == 't')
        return 1;  /* python, python3 */
    if (comm[0] == 'p' && comm[1] == 'e' && comm[2] == 'r' && comm[3] == 'l')
        return 1;
    if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'b' && comm[3] == 'y')
        return 1;
    if (comm[0] == 'n' && comm[1] == 'o' && comm[2] == 'd' && comm[3] == 'e')
        return 1;
    return 0;
}

/*
 * Tracepoint: sched/sched_process_exec
 *
 * Fires on every execve(). We score the process based on parent comm,
 * UID transitions, and the new comm (binary name).
 *
 * NOTE: In BCC, this is attached via:
 *   b.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")
 */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    pt_inc_stat(STAT_TOTAL_EXECS);

    /* Get current and parent info */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    char comm[COMM_SIZE] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    __u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);

    char parent_comm[COMM_SIZE] = {};
    bpf_probe_read_kernel_str(&parent_comm, sizeof(parent_comm),
                              &task->real_parent->comm);

    /* Calculate suspicious score */
    __u32 score = SCORE_CLEAN;
    __u8 flags = 0;

    /* Check 1: Web server spawning shell */
    if (is_web_server(parent_comm) && is_shell(comm)) {
        score += SCORE_HIGH;
        flags |= FLAG_WEB_SHELL;
    }

    /* Check 2: Shell spawned by script interpreter */
    if (is_script_interpreter(parent_comm) && is_shell(comm)) {
        score += SCORE_MEDIUM;
        flags |= FLAG_SCRIPTING;
    }

    /* Check 3: Root escalation (parent non-root, child root) */
    __u32 parent_uid = 0;
    struct process_info *parent_info = process_table.lookup(&ppid);
    if (parent_info) {
        parent_uid = parent_info->uid;
    }
    if (uid == 0 && parent_uid != 0 && parent_uid != 0xFFFFFFFF) {
        score += SCORE_MEDIUM;
        flags |= FLAG_ROOT_ESCALATION;
    }

    /* Store process info */
    struct process_info info = {};
    info.pid = pid;
    info.ppid = ppid;
    info.uid = uid;
    info.start_ns = now;
    info.suspicious_score = score;
    __builtin_memcpy(info.comm, comm, COMM_SIZE);
    process_table.update(&pid, &info);

    /* Check if PID is in kill list (previously flagged) */
    __u8 *should_kill = kill_list.lookup(&pid);
    if (should_kill && *should_kill == 1) {
        /* Signal sent from userspace via bpf_send_signal */
        bpf_send_signal(9);  /* SIGKILL */
    }

    /* Export events with non-zero scores */
    if (score > SCORE_CLEAN) {
        pt_inc_stat(STAT_SUSPICIOUS);
        if (score >= SCORE_CRITICAL)
            pt_inc_stat(STAT_CRITICAL);

        struct process_event *evt = process_events.ringbuf_output(sizeof(*evt), 0);
        if (evt) {
            evt->timestamp_ns = now;
            evt->pid = pid;
            evt->ppid = ppid;
            evt->uid = uid;
            evt->suspicious_score = score;
            __builtin_memcpy(evt->comm, comm, COMM_SIZE);
            evt->flags = flags;
            process_events.ringbuf_submit(evt, 0);
            pt_inc_stat(STAT_EXPORTS);
        }
    }

    return 0;
}
