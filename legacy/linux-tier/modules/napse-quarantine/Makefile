# modules/napse-quarantine/Makefile — IMAGE-BUILD-TIME build of the Ring-0 quarantine enforcement
# object + native loader. Mirrors modules/napse-capture/Makefile's structure and honesty posture.
#
# Runs in CI on the build host (clang/llvm + bpftool + a glibc aarch64 cross toolchain), NOT on
# the device — the bootc image ships no compiler (base/Containerfile Layer A). This dev box
# happens to carry clang-18/bpftool/aarch64-linux-gnu-gcc, which is how this module's `.bpf.o` +
# aarch64 loader were built and validated on a live Pi 4 (10.200.0.4) for the first cut — see
# modules/napse-quarantine/README.md for the exact transcript.
#
# WHY aarch64-unknown-linux-gnu, NOT -musl (unlike most of this repo's static-musl binaries):
# libbpf's C source (vendored via libbpf-sys) uses glibc's _FORTIFY_SOURCE-wrapped symbols
# (__snprintf_chk, open64/fopen64/mmap64, ...) once compiled with a GLIBC cross compiler
# (aarch64-linux-gnu-gcc) — those symbols do not exist in musl, so a musl-target build with a
# glibc C compiler fails at final link with a wall of `undefined reference to __snprintf_chk`
# (reproduced on this dev box; see the README). The two correct fixes are (a) a musl-targeting C
# cross-compiler (not present here, would need musl-cross-make or an extra toolchain download),
# or (b) target the Pi's ACTUAL C library — Debian 12 aarch64 glibc 2.36 — directly. (b) is what
# `hookprobe-evidence`'s own documented cross-recipe already does (see
# builder/mkosi-arm64/build-arm64.sh:120); this module follows the same precedent rather than
# introducing a third convention.

ARCH        ?= $(shell uname -m)
BPF_ARCH    := $(patsubst aarch64,arm64,$(patsubst x86_64,x86,$(ARCH)))
STAGE       := sysext
BPF_OUT     := $(STAGE)/usr/lib/hookprobe/bpf
BIN_OUT     := $(STAGE)/usr/lib/hookprobe/bin
BPF_DIR     := bpf

CLANG       ?= clang
BPFTOOL     ?= bpftool                 # on this dev box: /usr/lib/linux-tools-6.8.0-134/bpftool
                                        # (the /usr/sbin/bpftool shim warns "not found for kernel
                                        # <running>" because Ubuntu packages it per-kernel; any
                                        # bpftool binary can `btf dump`/`prog load` regardless of
                                        # the RUNNING kernel version — see README for the exact
                                        # command that worked here).
CARGO       ?= cargo
REPO        ?= $(abspath $(CURDIR)/../..)
TARGET      ?= aarch64-unknown-linux-gnu
CC_TRIPLE   ?= aarch64-linux-gnu-gcc
RELEASE_DIR ?= $(REPO)/target/$(TARGET)/release
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

.PHONY: all bpf loader vmlinux-h verify clean

all: vmlinux-h bpf loader

# --- CO-RE object: one TC-bpf program, two hash maps (ips, macs) + one stats array -------------
bpf: vmlinux-h                ## REQUIRES: clang -target bpf + libbpf headers (kernel >=4.1 for TC-bpf)
	install -d $(BPF_OUT)
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	  -I$(BPF_OUT) -I$(BPF_DIR) -c $(BPF_DIR)/quarantine.bpf.c -o $(BPF_OUT)/quarantine.bpf.o

# --- vmlinux.h for CO-RE -------------------------------------------------------------------------
# CO-RE relocates against the TARGET kernel's OWN BTF at load time (not this header) — compiling
# against the build host's BTF is fine; the struct SHAPES this program touches (ethhdr, iphdr,
# __sk_buff) are stable across the kernels this ships to. See docs/adr/0005 point 6.
vmlinux-h:
	install -d $(BPF_OUT)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(BPF_OUT)/vmlinux.h

# --- native loader (Rust, libbpf-rs) --------------------------------------------------------------
# `vendored` (not just libbpf-rs's default `vendored-libbpf`) also vendors+builds libelf/zlib from
# source for the target — this dev box (and most CI images) have no aarch64-glibc system
# libelf/libz to link against otherwise. Needs: autoconf/automake/libtool/autopoint/flex/bison
# (elfutils' build system) in addition to clang + the aarch64 gcc cross toolchain.
loader:                        ## REQUIRES: cargo + aarch64-linux-gnu-gcc + autotools (see above)
	CC_aarch64_unknown_linux_gnu=$(CC_TRIPLE) \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$(CC_TRIPLE) \
	$(CARGO) build --release --target $(TARGET) -p napse-quarantine --features bpf
	install -D -m0755 $(RELEASE_DIR)/napse-quarantine $(BIN_OUT)/napse-quarantine

# --- load-test in a CI kernel VM (can't run here reliably — this dev box DID verifier-load it
#     locally against ITS OWN kernel/BTF as a smoke test; see README for that transcript) --------
verify:
	@echo "TODO(CI): in a VM with a >=5.x BTF kernel, load quarantine.bpf.o at clsact ingress on a"
	@echo "          veth pair, assert verifier-clean + TC_ACT_SHOT on a matched key, per target arch."

clean:
	rm -f $(BPF_OUT)/*.o $(BPF_OUT)/vmlinux.h $(BIN_OUT)/napse-quarantine
