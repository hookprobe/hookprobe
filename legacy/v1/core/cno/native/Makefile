# Phase 27c native extensions
#
# Build: make
# Install: copy libpopcount.so to /home/ubuntu/hookprobe/core/cno/native/
# Test: python3 -c "from core.cno.native import popcount; print(popcount.bit_density(b'\\x55' * 1024))"

CC      ?= gcc
CFLAGS  := -O3 -fPIC -Wall -Wextra -std=c99
ARCH    := $(shell uname -m)

# Architecture-specific tuning
ifeq ($(ARCH),x86_64)
  CFLAGS += -march=native -mpopcnt
endif
ifeq ($(ARCH),aarch64)
  CFLAGS += -march=armv8-a
endif

.PHONY: all clean test popcount xsk sort

all: popcount xsk sort

popcount: libpopcount.so
libpopcount.so: popcount.c
	$(CC) $(CFLAGS) -shared -o $@ $<
	@echo "Built libpopcount.so ($(ARCH))"

xsk: libxsk_consumer.so
libxsk_consumer.so: xsk_consumer.c
	$(CC) $(CFLAGS) -shared -o $@ $< -lxdp -lbpf -lelf -lz
	@echo "Built libxsk_consumer.so ($(ARCH))"

sort: libsynaptic_sort.so
libsynaptic_sort.so: synaptic_sort.zig
	zig build-lib synaptic_sort.zig -O ReleaseFast -dynamic -fPIC -fno-stack-check
	@echo "Built libsynaptic_sort.so ($(ARCH))"

clean:
	rm -f libpopcount.so libxsk_consumer.so libsynaptic_sort.so libsynaptic_sort.so.o

test: $(TARGET)
	@python3 -c "import ctypes; \
		lib = ctypes.CDLL('./$(TARGET)'); \
		lib.popcount_buffer.restype = ctypes.c_uint64; \
		lib.popcount_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]; \
		buf = b'\\xff' * 131072; \
		import time; t = time.perf_counter(); \
		n = lib.popcount_buffer(buf, len(buf)); \
		dt = time.perf_counter() - t; \
		print(f'popcount: {n} bits set in {dt*1e6:.1f}us'); \
		t = time.perf_counter(); \
		n_py = sum(bin(b).count('1') for b in buf); \
		dt_py = time.perf_counter() - t; \
		print(f'pure-py:  {n_py} bits set in {dt_py*1e6:.1f}us'); \
		print(f'speedup:  {dt_py/dt:.1f}x')"
