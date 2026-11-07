# modules/napse-l2guard/Makefile — IMAGE-BUILD-TIME build of the Ring-0 malformed-frame drop
# object + native loader. Mirrors modules/napse-quarantine/Makefile's structure and honesty posture
# exactly (same toolchain, same aarch64-gnu-not-musl rationale, same dev-box provenance).
#
# Runs in CI on the build host (clang/llvm + bpftool + a glibc aarch64 cross toolchain), NOT on the
# device — the bootc image ships no compiler (base/Containerfile Layer A). Built + verified on this
# dev box (clang-18, libbpf-dev, the same aarch64 exact-glibc-2.36 sysroot trail
# modules/napse-quarantine/README.md documents) as the first cut — see this module's README.

ARCH        ?= $(shell uname -m)
BPF_ARCH    := $(patsubst aarch64,arm64,$(patsubst x86_64,x86,$(ARCH)))
STAGE       := sysext
BPF_OUT     := $(STAGE)/usr/lib/hookprobe/bpf
BIN_OUT     := $(STAGE)/usr/lib/hookprobe/bin
BPF_DIR     := bpf

CLANG       ?= clang
BPFTOOL     ?= bpftool
CARGO       ?= cargo
REPO        ?= $(abspath $(CURDIR)/../..)
TARGET      ?= aarch64-unknown-linux-gnu
CC_TRIPLE   ?= aarch64-linux-gnu-gcc
RELEASE_DIR ?= $(REPO)/target/$(TARGET)/release
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
# The exact-match Debian 12 (bookworm) arm64 glibc 2.36 cross wrapper documented in
# modules/napse-quarantine/README.md — same recipe, not re-derived here.
CC_aarch64_unknown_linux_gnu           ?= /tmp/aarch64-sysroot-gcc
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER ?= /tmp/aarch64-sysroot-gcc

.PHONY: all bpf loader vmlinux-h verify clean

all: vmlinux-h bpf loader

# --- CO-RE object: ONE TC-bpf program, no maps besides a tiny 2-entry stats array ----------------
# PROVEN (2026-07-05, this dev box): byte-identical output compiling with -D__TARGET_ARCH_x86 vs
# -D__TARGET_ARCH_arm64 (same precedent as quarantine.h documents for its own object) — this
# program touches no PT_REGS/register-layout macro, so ONE arch-less bpf-object digest is the
# honest representation in module.yaml, not a gap.
bpf: vmlinux-h                ## REQUIRES: clang -target bpf + libbpf headers (kernel >=4.1 for TC-bpf)
	install -d $(BPF_OUT)
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	  -I$(BPF_OUT) -I$(BPF_DIR) -c $(BPF_DIR)/l2guard.bpf.c -o $(BPF_OUT)/l2guard.bpf.o

# --- vmlinux.h for CO-RE (build-intermediate only — NOT a staged/shipped artifact; see the doc
#     comment on why the checked-in sysext/ tree here omits it, unlike napse-quarantine's) --------
vmlinux-h:
	install -d $(BPF_OUT)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(BPF_OUT)/vmlinux.h

# --- native loader (Rust; libbpf ONLY behind --features bpf; no reconcile state, unlike
#     napse-quarantine — this program has nothing external to mirror into a map) -----------------
loader:                        ## REQUIRES: cargo + aarch64-linux-gnu-gcc + autotools (elfutils build deps)
	CC_aarch64_unknown_linux_gnu=$(CC_aarch64_unknown_linux_gnu) \
	CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$(CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER) \
	$(CARGO) build --release --target $(TARGET) -p napse-l2guard --features bpf
	install -D -m0755 $(RELEASE_DIR)/napse-l2guard $(BIN_OUT)/napse-l2guard

# --- load-test in a CI kernel VM (this dev box could NOT do this locally — no root/CAP_BPF; see
#     README's honesty section: `clang -target bpf` compiled clean, `bpftool prog load` failed
#     with "Operation not permitted", exactly the missing-privilege case, not a program defect) ---
verify:
	@echo "TODO(CI): in a VM with root/CAP_BPF and a >=5.x BTF kernel, load l2guard.bpf.o at clsact"
	@echo "          ingress on a veth pair, feed it the same fixture frames"
	@echo "          loader/src/predicates.rs's tests assert on in Rust, and assert TC_ACT_SHOT/OK"
	@echo "          match per fixture, per target arch."

clean:
	rm -f $(BPF_OUT)/*.o $(BPF_OUT)/vmlinux.h $(BIN_OUT)/napse-l2guard
