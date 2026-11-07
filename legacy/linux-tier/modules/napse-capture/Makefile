# modules/napse-capture/Makefile — IMAGE-BUILD-TIME build of the XDP/eBPF sysext.
#
# Runs in CI on the build host (which HAS clang/llvm + Zig + the kernel headers/BTF),
# NOT on the device. The DEVICE never compiles eBPF (immutable image; no clang baked
# in — see base/Containerfile Layer A comment + runtime-engine-map open-Q 2).
#
# DECISION (locked here, was runtime-engine-map open-Q 2):
#   PRE-COMPILED CO-RE objects baked into the sysext  >  on-device compilation.
#   Rationale:
#     - bootc rootfs is immutable + read-only /usr; on-device compile would need
#       clang/llvm/headers in the image (megabytes, attack surface, drift).
#     - CO-RE (Compile Once, Run Everywhere) + BTF relocations let ONE object run
#       across kernel versions without per-host recompiles — exactly the bootc model.
#     - The object is then covered by the sysext's cosign signature (trust-nothing-unsigned).
#
# HONESTY: this Makefile CANNOT run in the current dev environment (no BPF toolchain,
# no kernel BTF, no root). It is the reviewed CI recipe; targets are marked where a
# real toolchain / kernel is required.

ARCH        ?= $(shell uname -m)        # CI sets per target: aarch64 | x86_64 | riscv64
# clang -target bpf wants the SHORT arch for __TARGET_ARCH_* (x86 not x86_64, arm64 not aarch64).
BPF_ARCH    := $(patsubst aarch64,arm64,$(patsubst x86_64,x86,$(ARCH)))
V1_AEGIS    ?= $(HOME)/hookprobe/core/napse/aegis
V1_KERNEL   ?= $(HOME)/hookprobe/core/napse/kernel
STAGE       := sysext
XDP_OUT     := $(STAGE)/usr/lib/hookprobe/xdp
BIN_OUT     := $(STAGE)/usr/lib/hookprobe/bin
# V2 unified CO-RE sources (napse_detect.bpf.c + .h). NOTE: no trailing spaces before EOL — make
# would capture them into the value and break `$(BPF_DIR)/napse_detect.bpf.c`.
BPF_DIR     := bpf

CLANG       ?= clang
ZIG         ?= zig
BPFTOOL     ?= bpftool
CARGO       ?= cargo
REPO        ?= $(abspath $(CURDIR)/../..)
# Where the Rust loader binaries land. CI cross-builds override RELEASE_DIR to target/<triple>/release.
RELEASE_DIR ?= $(REPO)/target/release
# CO-RE needs the TARGET kernel's BTF. On a build host this is vmlinux BTF;
# for cross-arch we ship a per-arch vmlinux.h generated from that arch's BTF.
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

.PHONY: all bpf-zig bpf-c bpf-unified btfgen loader vmlinux-h verify clean
# V2 default: the UNIFIED CO-RE core (ADR 0005) + BTFGen. The V1 bpf-zig/bpf-c objects are kept for
# the ddos_mitigation drop fast-paths; bpf-unified is the new one-object XDP+TC detection engine.
all: vmlinux-h bpf-unified btfgen bpf-c loader verify

# --- Zig XDP passive-inspect program → BPF object (the crown jewel) ----------
# Mirrors V1 build.zig: target bpfel-freestanding-none, ReleaseFast.
bpf-zig:                       ## REQUIRES: zig + bpf target
	cd $(V1_AEGIS) && $(ZIG) build      # produces zig-out/bin/aegis_xdp.o
	install -D -m0644 $(V1_AEGIS)/zig-out/bin/aegis_xdp.o $(XDP_OUT)/aegis_xdp.o
	# TODO: verify the object loads against a BTF kernel in a CI VM (see verify:).

# --- V2 UNIFIED detection core (CO-RE): ONE object, xdp + tc wrappers (ADR 0005) --------------
# napse_detect.bpf.c compiles to a single object carrying SEC("xdp") AND SEC("tc") programs sharing
# one detection core (bpf_ct_lookup stateful fast-path, WAN/LAN policy split). The loader attaches
# napse_xdp on NICs with native XDP, else napse_tc at clsact (incl. all Wi-Fi). -g keeps BTF for CO-RE.
bpf-unified: vmlinux-h         ## REQUIRES: clang -target bpf + libbpf headers (kernel >=5.19 to run)
	install -d $(XDP_OUT)
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	  -I$(XDP_OUT) -I$(BPF_DIR) -c $(BPF_DIR)/napse_detect.bpf.c -o $(XDP_OUT)/napse_detect.bpf.o
	$(BPFTOOL) gen skeleton $(XDP_OUT)/napse_detect.bpf.o > $(BIN_OUT)/napse_detect.skel.h 2>/dev/null || true

# --- BTFGen: minimal per-kernel BTF for BSP kernels without CONFIG_DEBUG_INFO_BTF (ADR 0005) ---
# For each supported target kernel's BTF (from btfhub-archive), emit a tiny BTF tailored to this
# object's CO-RE relocations. libbpf loads the matching blob when /sys/kernel/btf/vmlinux is absent
# (e.g. some RK3588 BSPs). Shipped in — and covered by — the cosign-signed sysext.
btfgen: bpf-unified            ## REQUIRES: bpftool >=7 + a BTF corpus (btfhub-archive)
	install -d $(XDP_OUT)/btf
	@echo "TODO(CI): for kver in <targets>: bpftool gen min_core_btf <kver.btf> \\"
	@echo "            $(XDP_OUT)/btf/<kver>.btf $(XDP_OUT)/napse_detect.bpf.o"

# --- C eBPF drop fast-path objects (CO-RE) -----------------------------------
# gate / synwall / flow_ctrl — attached ONLY when ddos_mitigation is granted.
bpf-c: vmlinux-h               ## REQUIRES: clang -target bpf + libbpf headers
	for src in xdp_gate xdp_synwall xdp_flow_ctrl ringbuf_events; do \
	  $(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	    -I$(XDP_OUT) -c $(V1_KERNEL)/$$src.c -o $(XDP_OUT)/$$src.o ; \
	done
	# -g keeps BTF in the object (required for CO-RE relocations).

# --- vmlinux.h for CO-RE (per target arch) -----------------------------------
vmlinux-h:                     ## REQUIRES: bpftool + target-arch BTF
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $(XDP_OUT)/vmlinux.h
	# TODO(BTF/kernel matrix): generate vmlinux.h from EACH supported target's BTF
	#   (Pi5 6.6/6.12, RK3588 6.1 BSP / 6.14 mainline, N100 generic, cloud).
	#   CO-RE relocates across versions but the build needs that arch's BTF, and
	#   kernels WITHOUT CONFIG_DEBUG_INFO_BTF (some vendor BSPs) need a shipped
	#   BTF blob + libbpf BPF_F_... fallback. This matrix is the real open risk.

# --- userspace loader (Rust napse-loader, libbpf-rs) — the V2 replacement for the Zig loader -----
# Builds napse-loader WITH the `bpf` feature (attaches napse_detect.bpf.o + drains the ringbuf) plus
# the napse-dpi mirror sensor, and installs BOTH into the sysext bin. napse-capture.service execs
# napse-loader; napse-dpi.service execs napse-dpi. (V1 Zig loader kept as `loader-zig` for reference.)
loader:                        ## REQUIRES: cargo + libbpf-dev/libelf/zlib + clang
	$(CARGO) build --release -p napse-loader --features bpf $(CARGO_FLAGS)
	install -D -m0755 $(RELEASE_DIR)/napse-loader   $(BIN_OUT)/napse-loader
	install -D -m0755 $(RELEASE_DIR)/napse-dpi       $(BIN_OUT)/napse-dpi
	install -D -m0755 $(RELEASE_DIR)/hydra-feedsync  $(BIN_OUT)/hydra-feedsync

loader-zig:                    ## legacy V1 Zig loader (reference only)
	cd $(V1_AEGIS) && $(ZIG) build      # produces zig-out/bin/aegis-loader
	install -D -m0755 $(V1_AEGIS)/zig-out/bin/aegis-loader $(BIN_OUT)/napse-xdp-loader

# --- load-test the objects in a CI kernel VM (can't run here) ----------------
verify:                        ## REQUIRES: a privileged CI VM with a BTF kernel
	@echo "TODO: in a CI VM, 'bpftool prog load' / xdp-loader load each .o on a"
	@echo "      veth + dummy-mirror, assert verifier-clean + XDP_PASS, per target arch."

clean:
	rm -f $(XDP_OUT)/*.o $(XDP_OUT)/vmlinux.h $(BIN_OUT)/napse-xdp-loader
	rm -rf $(XDP_OUT)/btf $(BIN_OUT)/napse_detect.skel.h
