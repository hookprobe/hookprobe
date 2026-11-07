/*
 * Phase 27e: AF_XDP (XSK) zero-copy consumer.
 *
 * Replaces the BPF RINGBUF + mmap + struct.unpack path (9 copies/event)
 * with shared-memory frame access (2 copies: NIC→UMEM via DMA, UMEM
 * stays mmap'd in the same address space as the Python process).
 *
 * Design constraints (from Phase 27d lesson):
 *   - Per-frame ctypes calls would dominate the win. So this library
 *     exposes a BATCH consumer: caller provides a callback OR a
 *     pre-allocated array; we fill many frame descriptors per round trip.
 *   - All hot data (frame_addr, len, src_ip extracted from packet) is
 *     written into a caller-owned struct array. Python code reads from
 *     that array via numpy/ctypes once per batch, not per frame.
 *
 * This is a minimal AF_XDP consumer — relies on:
 *   - libxdp / libbpf (xsk.h)
 *   - kernel ≥ 5.6 (XSK_UNALIGNED_CHUNK_FLAG)
 *
 * Build:
 *   gcc -O3 -fPIC -shared -o libxsk_consumer.so xsk_consumer.c \
 *       -lxdp -lbpf -lelf -lz
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 27.0.0
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>     /* XDP_FLAGS_* */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

/* xdp/xsk.h provides high-level XSK API on top of raw if_xdp.h */
#include <xdp/xsk.h>

/* ─── Configuration ────────────────────────────────────────────── */
#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE  /* 4096 */
#define BATCH_SIZE         64
#define INVALID_UMEM_FRAME UINT64_MAX

/* ─── Frame descriptor (caller reads this array) ───────────────── */
struct xsk_frame_desc {
    uint64_t addr;        /* UMEM offset where packet bytes are */
    uint32_t len;          /* packet length */
    uint32_t src_ip;       /* extracted L3 src IP (network byte order) */
    uint32_t dst_ip;       /* extracted L3 dst IP (network byte order) */
    uint16_t src_port;     /* extracted L4 src port (network byte order) */
    uint16_t dst_port;     /* extracted L4 dst port */
    uint8_t  proto;        /* IP proto (TCP=6, UDP=17, ICMP=1) */
    uint8_t  tcp_flags;    /* if proto==TCP */
    uint16_t _pad;
} __attribute__((aligned(32)));

/* ─── XSK socket state ─────────────────────────────────────────── */
struct xsk_state {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    void *umem_buffer;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
    int xsk_fd;
};

/*
 * Lightweight L3/L4 parser. Fills src_ip/dst_ip/src_port/dst_port/proto
 * from a raw Ethernet frame. Returns 0 on success, -1 on parse failure.
 * No allocation, no syscalls — pure ALU.
 */
static int parse_packet(const uint8_t *pkt, uint32_t len,
                         struct xsk_frame_desc *desc) {
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) return -1;
    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    /* Only IPv4 for now */
    if (eth->h_proto != htons(ETH_P_IP)) return -1;

    const struct iphdr *iph = (const struct iphdr *)(pkt + sizeof(struct ethhdr));
    desc->src_ip = iph->saddr;
    desc->dst_ip = iph->daddr;
    desc->proto = iph->protocol;

    uint32_t ihl_bytes = iph->ihl * 4;
    const uint8_t *l4 = (const uint8_t *)iph + ihl_bytes;
    if ((const uint8_t *)l4 + 4 > pkt + len) return 0; /* no L4 hdr; OK */

    if (iph->protocol == IPPROTO_TCP) {
        const struct tcphdr *th = (const struct tcphdr *)l4;
        desc->src_port = th->source;
        desc->dst_port = th->dest;
        /* TCP flags byte is at offset 13; combine all into one byte */
        desc->tcp_flags = (uint8_t)(((th->fin) << 0) | ((th->syn) << 1)
                                  | ((th->rst) << 2) | ((th->psh) << 3)
                                  | ((th->ack) << 4) | ((th->urg) << 5));
    } else if (iph->protocol == IPPROTO_UDP) {
        const struct udphdr *uh = (const struct udphdr *)l4;
        desc->src_port = uh->source;
        desc->dst_port = uh->dest;
        desc->tcp_flags = 0;
    } else {
        desc->src_port = 0;
        desc->dst_port = 0;
        desc->tcp_flags = 0;
    }
    return 0;
}

/* ─── Public API ──────────────────────────────────────────────── */

/*
 * Open an AF_XDP socket on the given interface + queue.
 * Returns opaque handle (cast to void* for ctypes), or NULL on failure.
 *
 * The interface MUST already have an XDP program loaded that redirects
 * to the xsks_map. See xdp_gate.c — it has BPF_XSKMAP(xsks_map, 4)
 * declared. The consumer attaches to xsks_map[queue_id].
 */
struct xsk_state *xsk_consumer_open(const char *ifname, uint32_t queue_id) {
    struct xsk_state *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    /* Allocate UMEM buffer */
    int err = posix_memalign(&s->umem_buffer, getpagesize(),
                              NUM_FRAMES * FRAME_SIZE);
    if (err) {
        fprintf(stderr, "xsk: posix_memalign failed: %s\n", strerror(err));
        free(s);
        return NULL;
    }

    struct xsk_umem_config umem_cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    if (xsk_umem__create(&s->umem, s->umem_buffer,
                          NUM_FRAMES * FRAME_SIZE,
                          &s->fill, &s->comp, &umem_cfg)) {
        fprintf(stderr, "xsk: umem create failed: %s\n", strerror(errno));
        free(s->umem_buffer);
        free(s);
        return NULL;
    }

    /* Initialize free-frame stack */
    for (uint32_t i = 0; i < NUM_FRAMES; i++) {
        s->umem_frame_addr[i] = i * FRAME_SIZE;
    }
    s->umem_frame_free = NUM_FRAMES;

    /* Create the XSK socket */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libxdp_flags = 0,
        .xdp_flags = XDP_FLAGS_SKB_MODE,  /* generic mode (works on all NICs) */
        .bind_flags = 0,                   /* copy mode (zero-copy needs driver support) */
    };

    if (xsk_socket__create(&s->xsk, ifname, queue_id, s->umem,
                            &s->rx, &s->tx, &xsk_cfg)) {
        fprintf(stderr, "xsk: socket create failed on %s queue %u: %s\n",
                ifname, queue_id, strerror(errno));
        xsk_umem__delete(s->umem);
        free(s->umem_buffer);
        free(s);
        return NULL;
    }
    s->xsk_fd = xsk_socket__fd(s->xsk);

    /* Pre-populate the FILL ring so the kernel has buffers to write into */
    uint32_t idx_fq = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&s->fill,
                                                XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                                &idx_fq);
    for (uint32_t i = 0; i < reserved; i++) {
        *xsk_ring_prod__fill_addr(&s->fill, idx_fq + i) =
            s->umem_frame_addr[--s->umem_frame_free];
    }
    xsk_ring_prod__submit(&s->fill, reserved);

    return s;
}

/*
 * Receive up to `max` frames into the caller's descriptor array.
 * Returns the number of frames received (0 if none ready).
 *
 * Frame addresses point into the UMEM (already mmap'd in this process).
 * Caller can read packet bytes via xsk_consumer_get_data(state, addr).
 *
 * After processing, the caller MUST call xsk_consumer_release_frames()
 * to return descriptors to the kernel's FILL ring.
 */
int xsk_consumer_recv(struct xsk_state *s,
                       struct xsk_frame_desc *out,
                       int max) {
    if (max > BATCH_SIZE) max = BATCH_SIZE;

    uint32_t idx_rx = 0;
    int rcvd = xsk_ring_cons__peek(&s->rx, max, &idx_rx);
    if (rcvd <= 0) return 0;

    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&s->rx, idx_rx + i);
        out[i].addr = d->addr;
        out[i].len = d->len;
        const uint8_t *pkt = xsk_umem__get_data(s->umem_buffer, d->addr);
        parse_packet(pkt, d->len, &out[i]);
    }

    xsk_ring_cons__release(&s->rx, rcvd);
    return rcvd;
}

/*
 * After processing a batch, return the frame addresses to the FILL ring
 * so the kernel can use them for new incoming packets.
 */
void xsk_consumer_release_frames(struct xsk_state *s,
                                   struct xsk_frame_desc *frames,
                                   int n) {
    uint32_t idx_fq = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&s->fill, n, &idx_fq);
    for (uint32_t i = 0; i < reserved; i++) {
        *xsk_ring_prod__fill_addr(&s->fill, idx_fq + i) = frames[i].addr;
    }
    xsk_ring_prod__submit(&s->fill, reserved);
}

/*
 * Get a pointer to packet data at a UMEM offset.
 * Returned pointer is valid until xsk_consumer_release_frames() is called
 * for that frame. ctypes can wrap this as c_char_p for read-only access.
 */
const uint8_t *xsk_consumer_get_data(struct xsk_state *s, uint64_t addr) {
    return xsk_umem__get_data(s->umem_buffer, addr);
}

/*
 * Get the AF_XDP socket file descriptor (for poll/epoll integration).
 */
int xsk_consumer_fd(struct xsk_state *s) {
    return s->xsk_fd;
}

/*
 * Clean shutdown.
 */
void xsk_consumer_close(struct xsk_state *s) {
    if (!s) return;
    if (s->xsk) xsk_socket__delete(s->xsk);
    if (s->umem) xsk_umem__delete(s->umem);
    if (s->umem_buffer) free(s->umem_buffer);
    free(s);
}
