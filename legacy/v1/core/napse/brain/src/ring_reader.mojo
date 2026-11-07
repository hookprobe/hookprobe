# =============================================================================
# Napse Ring Buffer Reader - C FFI Interface to Aegis Shared Memory
# =============================================================================
#
# This module maps the Aegis shared memory ring buffer into Napse's address
# space. It provides a zero-copy read interface for consuming feature vectors
# produced by the Aegis XDP program.
#
# Memory layout matches Aegis ring_buffer.zig (C-compatible extern structs).

from memory import UnsafePointer, DTypePointer
from sys.info import simdwidthof


# Must match Aegis ring_buffer.zig
alias FEATURE_DIMS: Int = 32
alias MAX_RAW_SLICE: Int = 1500
alias RING_MAGIC: UInt32 = 0x53474541  # "AEGS"
alias RING_VERSION: UInt32 = 1


@value
struct RingEntry:
    """A single entry in the Aegis -> Napse ring buffer.
    Layout matches the C-compatible extern struct in ring_buffer.zig.
    """
    var sequence: UInt64
    var timestamp: UInt64
    var feature_vector: InlinedFixedVector[Float32, FEATURE_DIMS]
    var src_ip: UInt32
    var dst_ip: UInt32
    var src_port: UInt16
    var dst_port: UInt16
    var proto: UInt8
    var entropy: Float32
    var tcp_flags: UInt8
    var raw_len: UInt16

    fn __init__(out self):
        self.sequence = 0
        self.timestamp = 0
        self.feature_vector = InlinedFixedVector[Float32, FEATURE_DIMS]()
        for i in range(FEATURE_DIMS):
            self.feature_vector.append(0.0)
        self.src_ip = 0
        self.dst_ip = 0
        self.src_port = 0
        self.dst_port = 0
        self.proto = 0
        self.entropy = 0.0
        self.tcp_flags = 0
        self.raw_len = 0


@value
struct RingHeader:
    """Ring buffer header stored at the beginning of shared memory."""
    var magic: UInt32
    var version: UInt32
    var capacity: UInt32
    var entry_size: UInt32
    var write_seq: UInt64
    var read_seq: UInt64
    var total_written: UInt64
    var total_dropped: UInt64


struct RingReader:
    """Lock-free ring buffer consumer for reading Aegis feature vectors.

    Usage:
        var reader = RingReader("/dev/shm/aegis-napse-ring")
        while True:
            var batch = reader.read_batch[8]()
            if batch.size > 0:
                engine.classify(batch)
    """
    var path: String
    var capacity: UInt32
    var local_read_seq: UInt64

    fn __init__(out self, path: String):
        self.path = path
        self.capacity = 0
        self.local_read_seq = 0

    fn is_connected(self) -> Bool:
        """Check if the ring buffer is mapped and valid."""
        return self.capacity > 0

    fn available(self) -> UInt64:
        """Return the number of unread entries in the ring."""
        # In production, this reads from shared memory atomically
        return 0

    fn read_batch(self, batch_size: Int) -> List[RingEntry]:
        """Read up to batch_size entries from the ring buffer.

        Returns a list of RingEntry objects. Empty list if ring is empty.
        This is the primary interface for the Napse intent engine.
        """
        var entries = List[RingEntry]()

        # Production implementation:
        # 1. Atomic read of write_seq from shared memory
        # 2. Compare with local_read_seq
        # 3. For each available entry:
        #    a. Calculate slot index = read_seq & (capacity - 1)
        #    b. Copy feature vector from shared memory
        #    c. Increment local_read_seq
        # 4. Atomic store of read_seq to shared memory

        return entries

    fn stats(self) -> Tuple[UInt64, UInt64, UInt64]:
        """Return (total_written, total_dropped, current_backlog)."""
        return (0, 0, 0)
