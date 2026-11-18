THEORETICAL. DRAM 11.8 GB/s (Pi 5 measured, same SoC); eMMC 100,250 MB/s (assumed range); KV f16.
decode ceiling = bus share x bandwidth / bytes read per token; real decode is lower (compute, cache, scheduling)

| model | format | weights MiB | embed MiB | state @256/512 | scratch MiB | tokenizer+code MiB | total @512 MiB | bytes/token MiB | tok/s ceiling @100%/25% share | cold load s @100/250 MB/s | stream-from-eMMC s/token | fits SKU (AI budget) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B (GGUF header) | Q8_0 | 446 | 158 | 28.0 / 56.0 | 0.6 | 5.0 | 666 | 660 | 17 / 4 | 6.3 / 2.5 | 2.8 | 4 GB, 8 GB, 16 GB |
| Qwen3-0.6B (GGUF header) | Q4_0 | 236 | 158 | 28.0 / 56.0 | 0.6 | 5.0 | 456 | 450 | 25 / 6 | 4.1 / 1.7 | 1.9 | 4 GB, 8 GB, 16 GB |
| Qwen3-1.7B (GGUF header) | Q8_0 | 1428 | 315 | 28.0 / 56.0 | 0.7 | 5.0 | 1805 | 1799 | 6 / 2 | 18.3 / 7.3 | 7.5 | 8 GB, 16 GB |
| Qwen3-1.7B (GGUF header) | Q4_0 | 756 | 315 | 28.0 / 56.0 | 0.7 | 5.0 | 1133 | 1127 | 10 / 2 | 11.2 / 4.5 | 4.7 | 8 GB, 16 GB |
| Qwen3.5-0.8B (GGUF header) | Q8_0 | 504 | 258 | 22.3 / 25.3 | 1.0 | 7.0 | 795 | 787 | 14 / 4 | 8.0 / 3.2 | 3.3 | 4 GB, 8 GB, 16 GB |
| Qwen3.5-0.8B (GGUF header) | Q4_0 | 267 | 258 | 22.3 / 25.3 | 1.0 | 7.0 | 558 | 550 | 20 / 5 | 5.5 / 2.2 | 2.3 | 4 GB, 8 GB, 16 GB |
| BitNet b1.58 2B4T | Q8_0 | 2112 | 333 | 18.8 / 37.5 | 0.6 | 4.5 | 2487 | 2482 | 5 / 1 | 25.6 / 10.3 | 10.4 | 8 GB, 16 GB |
| BitNet b1.58 2B4T | Q4_0 | 1118 | 333 | 18.8 / 37.5 | 0.6 | 4.5 | 1493 | 1488 | 8 / 2 | 15.2 / 6.1 | 6.2 | 8 GB, 16 GB |
| BitNet b1.58 2B4T | T2 (ternary 2-bit, per-tensor scale) | 497 | 333 | 18.8 / 37.5 | 0.6 | 4.5 | 872 | 867 | 13 / 3 | 8.7 / 3.5 | 3.6 | 4 GB, 8 GB, 16 GB |
| BitNet b1.58 2B4T | T1.67 (ternary 3 weights / 5 bits, TL2-like) | 414 | 333 | 18.8 / 37.5 | 0.6 | 4.5 | 789 | 784 | 14 / 4 | 7.8 / 3.1 | 3.3 | 4 GB, 8 GB, 16 GB |
| RWKV-7 0.4B | Q8_0 | 309 | 136 | 6.2 / 6.2 | 0.3 | 2.0 | 453 | 383 | 29 / 7 | 4.7 / 1.9 | 1.6 | 4 GB, 8 GB, 16 GB |
| RWKV-7 0.4B | Q4_0 | 163 | 136 | 6.2 / 6.2 | 0.3 | 2.0 | 308 | 238 | 47 / 12 | 3.1 / 1.3 | 1.0 | 4 GB, 8 GB, 16 GB |
| RWKV-7 1.5B | Q8_0 | 1234 | 272 | 12.4 / 12.4 | 0.4 | 2.0 | 1521 | 1383 | 8 / 2 | 15.8 / 6.3 | 5.8 | 8 GB, 16 GB |
| RWKV-7 1.5B | Q4_0 | 653 | 272 | 12.4 / 12.4 | 0.4 | 2.0 | 940 | 802 | 14 / 4 | 9.7 / 3.9 | 3.4 | 4 GB, 8 GB, 16 GB |
| Security specialist (proposed) | int8 | 1.9 | - | 0.24 (1,000 devices) | 0.06 | 0.25 | 2.5 | 1.9 | n/a (per event, not per token) | <0.1 | n/a | 2 GB, 4 GB, 8 GB, 16 GB |

Sources: Qwen3-0.6B (GGUF header): GGUF header, Phase 0 file; Qwen3-1.7B (GGUF header): GGUF header, Phase 0 file; Qwen3.5-0.8B (GGUF header): GGUF header (vocab from embedding tensor 254279680/1024); BitNet b1.58 2B4T: model card values recalled -- UNVERIFIED; RWKV-7 0.4B: RWKV-7 paper arXiv 2503.14456 (L24, D1024); state derived, matches the research pass (6.2 MiB); RWKV-7 1.5B: RWKV-7 paper arXiv 2503.14456 (L24, D2048); FFN 4D assumed; Security specialist (proposed): design target, not a model
SKU AI budgets (planning assumptions, NEURO_CM5_RESOURCE_BUDGET §5): 2 GB <= 256 MiB, 4 GB <= 1024 MiB, 8 GB <= 2560 MiB, 16 GB <= 6144 MiB
