/**
 * NAPSE AF_XDP Receiver - Zero-Copy Packet Delivery
 *
 * Userspace C library for receiving packets from the eBPF XDP gate
 * via AF_XDP sockets. Provides zero-copy access to packet data
 * for the Rust protocol engine.
 *
 * This is NOT an eBPF program - it runs in userspace and is compiled
 * as a shared library linked by the Rust engine via FFI.
 *
 * AF_XDP provides 3-5x throughput improvement over AF-PACKET
 * (used by Suricata) by eliminating kernel-to-userspace copies.
 *
 * UMEM Configuration (per tier):
 *   Sentinel:  1024 frames, 2KB each  = 2MB UMEM
 *   Guardian:  4096 frames, 2KB each  = 8MB UMEM
 *   Fortress: 16384 frames, 2KB each  = 32MB UMEM
 *   Nexus:    65536 frames, 2KB each  = 128MB UMEM
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#ifndef NAPSE_AF_XDP_RX_H
#define NAPSE_AF_XDP_RX_H

#include <stdint.h>
#include <stdbool.h>

/* UMEM frame configuration */
#define FRAME_SIZE          2048
#define FRAME_HEADROOM      256

/* Default ring sizes */
#define DEFAULT_RX_SIZE     2048
#define DEFAULT_TX_SIZE     2048
#define DEFAULT_FILL_SIZE   4096
#define DEFAULT_COMP_SIZE   2048

/* Tier-specific UMEM sizes */
#define UMEM_FRAMES_SENTINEL   1024
#define UMEM_FRAMES_GUARDIAN   4096
#define UMEM_FRAMES_FORTRESS  16384
#define UMEM_FRAMES_NEXUS     65536

/**
 * AF_XDP socket configuration
 */
struct napse_xsk_config {
    const char *interface;       /* Network interface name */
    uint32_t queue_id;           /* NIC RX queue index */
    uint32_t umem_frames;        /* Number of UMEM frames */
    uint32_t frame_size;         /* Frame size (default 2048) */
    bool busy_poll;              /* Use busy-poll for low latency */
    uint32_t busy_poll_timeout;  /* Busy poll timeout in us */
};

/**
 * Received packet descriptor
 */
struct napse_packet {
    uint8_t *data;               /* Pointer to packet data */
    uint32_t len;                /* Packet length */
    uint64_t timestamp_ns;       /* Receive timestamp */
    uint32_t queue_id;           /* RX queue index */
};

/**
 * Callback for received packets.
 * Called by napse_xsk_poll() for each received packet.
 *
 * Return: 0 = continue, non-zero = stop polling
 */
typedef int (*napse_packet_cb)(const struct napse_packet *pkt, void *user_data);

/* ========================================================================
 * API Functions (implemented in af_xdp_rx_impl.c)
 * ======================================================================== */

/**
 * Create and configure an AF_XDP socket.
 * Returns: opaque handle, or NULL on failure.
 */
void *napse_xsk_create(const struct napse_xsk_config *config);

/**
 * Poll for received packets and invoke callback.
 * timeout_ms: 0 = non-blocking, -1 = infinite, >0 = timeout
 * Returns: number of packets processed, or -1 on error.
 */
int napse_xsk_poll(void *xsk, int timeout_ms, napse_packet_cb cb, void *user_data);

/**
 * Get socket file descriptor for epoll integration.
 */
int napse_xsk_fd(void *xsk);

/**
 * Destroy AF_XDP socket and free resources.
 */
void napse_xsk_destroy(void *xsk);

/**
 * Get AF_XDP statistics.
 */
struct napse_xsk_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_dropped;
    uint64_t fill_fail;
    uint64_t poll_timeout;
};

int napse_xsk_get_stats(void *xsk, struct napse_xsk_stats *stats);

#endif /* NAPSE_AF_XDP_RX_H */
