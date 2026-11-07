# Makefile — build execsnoop.bpf.o (CO-RE) on the BUILD HOST (clang/llvm + kernel BTF), NOT the device.
# Mirrors modules/napse-capture/Makefile: the immutable image never carries clang; it ships the signed
# .bpf.o. CO-RE relocations make one .bpf.o portable across kernels, so the arch only sets the register
# macro. Produces a per-arch object the host-telemetry loader mmaps + attaches.
#
#   make ARCH=x86     -> execsnoop.x86.bpf.o
#   make ARCH=arm64   -> execsnoop.arm64.bpf.o   (VMLINUX_BTF = the arm64 kernel's BTF)
ARCH        ?= x86
CLANG       ?= clang
BPFTOOL     ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
OUT         := execsnoop.$(ARCH).bpf.o

.PHONY: all clean verify
all: $(OUT)

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(OUT): execsnoop.bpf.c vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include \
		-c $< -o $@
	@echo "built $@ ($(shell stat -c %s $(OUT) 2>/dev/null) bytes)"

# load + auto-attach to sanity-check the verifier accepts it (build-host only; needs root + BTF)
verify: $(OUT)
	$(BPFTOOL) prog load $(OUT) /sys/fs/bpf/execsnoop_verify autoattach
	$(BPFTOOL) link show | grep sched_process_exec
	rm -f /sys/fs/bpf/execsnoop_verify

clean:
	rm -f execsnoop.*.bpf.o vmlinux.h
