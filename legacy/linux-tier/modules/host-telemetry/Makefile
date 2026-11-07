# modules/host-telemetry/Makefile — IMAGE-BUILD-TIME build of the eBPF host-telemetry sysext.
#
# Mirrors modules/napse-capture/Makefile: runs in CI on the build host (clang/llvm + per-arch BTF +
# the aarch64 C libs), NOT on the device. Ships the signed, pre-compiled CO-RE object + the loader;
# the immutable device never carries clang. CO-RE + BTF relocations → one .bpf.o per arch runs across
# kernel versions.
#
# PROVEN in dev (2026-07-02): the CO-RE object compiles for x86 AND arm64 (from the Pi's BTF), loads,
# verifies, attaches to sched_process_exec, and the loader streams 901 real execs in 4s. The loader
# (--features bpf) cross-compiles for aarch64 — libbpf-sys/libbpf/libbpf-rs all build; the ONLY extra
# CI dependency is aarch64 static libelf + libz for the final link (same as napse-loader --features bpf).
ARCH        ?= $(shell uname -m)                 # CI sets per target: aarch64 | x86_64 | riscv64
BPF_ARCH    := $(patsubst aarch64,arm64,$(patsubst x86_64,x86,$(ARCH)))
TRIPLE      ?= $(ARCH)-unknown-linux-musl
CLANG       ?= clang
BPFTOOL     ?= bpftool
CARGO       ?= cargo
REPO        ?= $(abspath $(CURDIR)/../..)
RELEASE_DIR ?= $(REPO)/target/$(TRIPLE)/release
# CO-RE needs the TARGET arch's BTF. Cross-arch: point VMLINUX_BTF at that arch's kernel BTF blob
# (e.g. pulled from the device: `cat /sys/kernel/btf/vmlinux`).
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
STAGE       := sysext
BPF_OUT     := $(STAGE)/usr/lib/hookprobe/bpf
BIN_OUT     := $(STAGE)/usr/lib/hookprobe/bin

.PHONY: all bpf loader stage verify clean
all: bpf loader stage

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

# CO-RE object for this arch (execsnoop.<arch>.bpf.o)
bpf: bpf/vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Ibpf -I/usr/include \
		-c bpf/execsnoop.bpf.c -o bpf/execsnoop.$(BPF_ARCH).bpf.o
	@echo "built bpf/execsnoop.$(BPF_ARCH).bpf.o"

# loader — needs aarch64 static libelf + libz in the CI image for the link (see header)
loader:
	CARGO_TARGET_$(shell echo $(TRIPLE) | tr 'a-z-' 'A-Z_')_LINKER=$(ARCH)-linux-gnu-gcc \
	  $(CARGO) build --release --target $(TRIPLE) -p hookprobe-execsnoop --features bpf

stage: bpf loader
	install -D -m0644 bpf/execsnoop.$(BPF_ARCH).bpf.o $(BPF_OUT)/execsnoop.bpf.o
	install -D -m0755 $(RELEASE_DIR)/hookprobe-execsnoop $(BIN_OUT)/hookprobe-execsnoop
	install -D -m0644 units/host-telemetry.service $(STAGE)/usr/lib/systemd/system/host-telemetry.service

# sanity-check the object verifies (build-host only; needs root + BTF)
verify: bpf
	$(BPFTOOL) prog load bpf/execsnoop.$(BPF_ARCH).bpf.o /sys/fs/bpf/execsnoop_v autoattach
	$(BPFTOOL) link show | grep sched_process_exec
	rm -f /sys/fs/bpf/execsnoop_v

clean:
	rm -f bpf/vmlinux.h bpf/execsnoop.*.bpf.o
	rm -rf $(STAGE)
