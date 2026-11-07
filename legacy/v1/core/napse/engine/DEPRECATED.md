# DEPRECATED: Rust Protocol Engine

**Status**: Deprecated as of NAPSE v2.0.0 (February 2026)

## What Replaced It

The Rust PyO3 engine has been replaced by the split-brain architecture:

| Component | Language | Purpose | Location |
|-----------|----------|---------|----------|
| **Aegis** | Zig 0.13 | XDP packet capture + feature extraction | `../aegis/` |
| **Napse Brain** | Mojo 2.0 | SIMD batch classification + HMM kill chain | `../brain/` |
| **Inspector** | Python 3.12 | Production fallback (AF_PACKET + Bayesian) | `../inspector/` |

## Why

1. **Zig** provides safer eBPF/XDP integration than Rust+libbpf-rs, with
   comptime-optimized protocol parsers and direct BPF map access
2. **Mojo** provides hardware-native SIMD vectorization (8-16 packets/cycle)
   that exceeds what Rust+ONNX could achieve for inference
3. **Python Inspector** provides a zero-dependency production fallback that
   works on any platform without Zig/Mojo toolchains

## Migration

The NapseOrchestrator (`main.py`) now uses a cascade:
1. Try Mojo napse-brain binary
2. Try Python PacketInspector
3. Fall back to synthesis-only mode

The Rust engine (`napse_engine` PyO3 module) is no longer loaded.

## Files Kept for Reference

This directory is kept for reference only. The PyO3 interface definitions
(`lib.rs`) document the record types and API surface that the Python
synthesis layer expects. These same record types are now produced by the
Mojo brain or Python Inspector.
