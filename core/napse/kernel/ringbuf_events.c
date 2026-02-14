/**
 * NAPSE Ring Buffer Events
 *
 * Exports lightweight flow metadata to userspace via eBPF ring buffer.
 * This produces the equivalent of Zeek's conn.log at near-zero cost
 * by exporting only metadata (32 bytes per event) without copying
 * actual packet data.
 *
 * Used when AF_XDP is not available or for flows that don't need
 * deep packet inspection.
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Ring buffer size: configurable per tier */
#ifndef RINGBUF_SIZE
#define RINGBUF_SIZE (1 << 20)  /* 1MB default (Fortress) */
#endif

/* Event types exported to userspace */
enum rb_event_type {
    RB_EVENT_NEW_FLOW = 1,       /* New connection detected */
    RB_EVENT_FLOW_UPDATE = 2,    /* Flow stats update */
    RB_EVENT_FLOW_CLOSE = 3,     /* Connection closed (FIN/RST/timeout) */
    RB_EVENT_DNS_QUERY = 4,      /* DNS query detected (port 53/5353) */
    RB_EVENT_DHCP = 5,           /* DHCP packet detected (port 67/68) */
    RB_EVENT_TLS_HELLO = 6,      /* TLS ClientHello detected */
};

/* Exported event structure (32 bytes, cache-line aligned) */
struct rb_event {
    __u64 timestamp_ns;          /* Kernel timestamp */
    __u32 src_ip;                /* Source IPv4 */
    __u32 dst_ip;                /* Destination IPv4 */
    __u16 src_port;              /* Source port */
    __u16 dst_port;              /* Destination port */
    __u8  proto;                 /* IP protocol (TCP=6, UDP=17) */
    __u8  event_type;            /* rb_event_type */
    __u8  tcp_flags;             /* TCP flags if applicable */
    __u8  pad;
    __u32 payload_len;           /* L4 payload length */
};

/* Ring buffer output map */
BPF_RINGBUF_OUTPUT(events, RINGBUF_SIZE);

/**
 * Export a flow event to the ring buffer.
 *
 * Called from the main XDP gate for packets that need
 * metadata-only export (no deep inspection needed).
 */
static __always_inline int rb_export_event(
    __u8 event_type,
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 tcp_flags,
    __u32 payload_len)
{
    struct rb_event *e = events.ringbuf_output(sizeof(*e), 0);
    if (!e)
        return -1;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->proto = proto;
    e->event_type = event_type;
    e->tcp_flags = tcp_flags;
    e->pad = 0;
    e->payload_len = payload_len;

    events.ringbuf_submit(e, 0);
    return 0;
}
