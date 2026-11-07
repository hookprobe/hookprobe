# Pre-compiled CO-RE objects land here (filled by CI, see ../../../../../Makefile).
#
# This directory is EMPTY in git on purpose: eBPF objects cannot be built on the dev
# box (no BPF toolchain / no kernel BTF). CI's `make all` populates:
#   aegis_xdp.o        passive out-of-band inspect (XDP_PASS) — the default object
#   xdp_synwall.o      SYN-flood drop wall      (inline; gated by ddos_mitigation)
#   xdp_gate.o         inline gate/drop logic   (inline; gated by ddos_mitigation)
#   xdp_flow_ctrl.o    flow-rate control        (inline; gated by ddos_mitigation)
#   xdp_drop_all.o     fail-closed block object (segment-down handler)  # TODO: author
#   vmlinux.h          per-arch BTF header for CO-RE relocation
#
# All are covered by the sysext's cosign signature once baked.
