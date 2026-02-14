# NAPSE eBPF/XDP Kernel Programs - Build System
#
# These programs are compiled using BCC (BPF Compiler Collection) at runtime.
# This Makefile is for development/validation only.
#
# In production, the C source is loaded as a string by the Python XDPManager
# and compiled via BCC's BPF() constructor (same as xdp_manager.py).

CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
    -Wall -Werror \
    -I/usr/include/$(shell uname -m)-linux-gnu

SRCS := xdp_gate.c conntrack_lite.c ringbuf_events.c
OBJS := $(SRCS:.c=.o)

.PHONY: all clean check

all: $(OBJS)

%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

check:
	@echo "Checking eBPF program syntax..."
	@for src in $(SRCS); do \
		echo "  Checking $$src..."; \
		$(CLANG) $(BPF_CFLAGS) -fsyntax-only $$src || exit 1; \
	done
	@echo "All eBPF programs OK"

clean:
	rm -f $(OBJS)

# Note: af_xdp_rx.c is a userspace C library, not an eBPF program.
# It is compiled separately as part of the Rust engine build.
