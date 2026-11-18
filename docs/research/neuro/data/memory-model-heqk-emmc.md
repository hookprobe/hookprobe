THEORETICAL. DRAM 11.8 GB/s (Pi 5 measured, same SoC); eMMC 3.1,12.5 MB/s (assumed range); KV f16.
decode ceiling = bus share x bandwidth / bytes read per token; real decode is lower (compute, cache, scheduling)

| model | format | weights MiB | embed MiB | state @512/2048 | scratch MiB | tokenizer+code MiB | total @2048 MiB | bytes/token MiB | tok/s ceiling @100%/25% share | cold load s @3.1/12.5 MB/s | stream-from-eMMC s/token | fits SKU (AI budget) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B (GGUF header) | Q8_0 | 446 | 158 | 56.0 / 224.0 | 0.7 | 5.0 | 834 | 828 | 14 / 3 | 204.3 / 50.7 | 69.4 | 4 GB, 8 GB, 16 GB |
| Qwen3-0.6B (GGUF header) | Q4_0 | 236 | 158 | 56.0 / 224.0 | 0.7 | 5.0 | 624 | 618 | 18 / 5 | 133.2 / 33.0 | 51.8 | 4 GB, 8 GB, 16 GB |
| Qwen3-1.7B (GGUF header) | Q8_0 | 1428 | 315 | 56.0 / 224.0 | 0.8 | 5.0 | 1973 | 1967 | 6 / 1 | 589.7 / 146.2 | 165.0 | 8 GB, 16 GB |
| Qwen3-1.7B (GGUF header) | Q4_0 | 756 | 315 | 56.0 / 224.0 | 0.8 | 5.0 | 1301 | 1295 | 9 / 2 | 362.4 / 89.9 | 108.7 | 8 GB, 16 GB |
| Qwen3.5-0.8B (GGUF header) | Q8_0 | 504 | 258 | 25.3 / 43.3 | 1.1 | 7.0 | 813 | 805 | 14 / 3 | 257.7 / 63.9 | 67.5 | 4 GB, 8 GB, 16 GB |
| Qwen3.5-0.8B (GGUF header) | Q4_0 | 267 | 258 | 25.3 / 43.3 | 1.1 | 7.0 | 576 | 568 | 20 / 5 | 177.4 / 44.0 | 47.6 | 4 GB, 8 GB, 16 GB |
| BitNet b1.58 2B4T | Q8_0 | 2112 | 333 | 37.5 / 150.0 | 0.7 | 4.5 | 2600 | 2594 | 4 / 1 | 826.8 / 205.1 | 217.6 | 16 GB |
| BitNet b1.58 2B4T | Q4_0 | 1118 | 333 | 37.5 / 150.0 | 0.7 | 4.5 | 1606 | 1601 | 7 / 2 | 490.7 / 121.7 | 134.3 | 8 GB, 16 GB |
| BitNet b1.58 2B4T | T2 (ternary 2-bit, per-tensor scale) | 497 | 333 | 37.5 / 150.0 | 0.7 | 4.5 | 985 | 980 | 11 / 3 | 280.6 / 69.6 | 82.2 | 4 GB, 8 GB, 16 GB |
| BitNet b1.58 2B4T | T1.67 (ternary 3 weights / 5 bits, TL2-like) | 414 | 333 | 37.5 / 150.0 | 0.7 | 4.5 | 902 | 897 | 13 / 3 | 252.6 / 62.6 | 75.2 | 4 GB, 8 GB, 16 GB |
| RWKV-7 0.4B | Q8_0 | 309 | 136 | 6.2 / 6.2 | 0.4 | 2.0 | 453 | 383 | 29 / 7 | 150.4 / 37.3 | 32.1 | 4 GB, 8 GB, 16 GB |
| RWKV-7 0.4B | Q4_0 | 163 | 136 | 6.2 / 6.2 | 0.4 | 2.0 | 308 | 238 | 47 / 12 | 101.3 / 25.1 | 19.9 | 4 GB, 8 GB, 16 GB |
| RWKV-7 1.5B | Q8_0 | 1234 | 272 | 12.4 / 12.4 | 0.6 | 2.0 | 1521 | 1383 | 8 / 2 | 509.5 / 126.3 | 116.0 | 8 GB, 16 GB |
| RWKV-7 1.5B | Q4_0 | 653 | 272 | 12.4 / 12.4 | 0.6 | 2.0 | 940 | 802 | 14 / 4 | 313.0 / 77.6 | 67.3 | 4 GB, 8 GB, 16 GB |
| Security specialist (proposed) | int8 | 1.9 | - | 0.24 (1,000 devices) | 0.06 | 0.25 | 2.5 | 1.9 | n/a (per event, not per token) | <0.1 | n/a | 2 GB, 4 GB, 8 GB, 16 GB |

Sources: Qwen3-0.6B (GGUF header): GGUF header, Phase 0 file; Qwen3-1.7B (GGUF header): GGUF header, Phase 0 file; Qwen3.5-0.8B (GGUF header): GGUF header (vocab from embedding tensor 254279680/1024); BitNet b1.58 2B4T: model card values recalled -- UNVERIFIED; RWKV-7 0.4B: RWKV-7 paper arXiv 2503.14456 (L24, D1024); state derived, matches the research pass (6.2 MiB); RWKV-7 1.5B: RWKV-7 paper arXiv 2503.14456 (L24, D2048); FFN 4D assumed; Security specialist (proposed): design target, not a model
SKU AI budgets (planning assumptions, NEURO_CM5_RESOURCE_BUDGET §5): 2 GB <= 256 MiB, 4 GB <= 1024 MiB, 8 GB <= 2560 MiB, 16 GB <= 6144 MiB
