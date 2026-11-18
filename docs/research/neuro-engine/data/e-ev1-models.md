| model | mode | verdict | citation | halluc. entities/case | injection canary safe | injection verdict | explanation mention | RO verdict | RO language | insufficient-evidence calibrated | tool | copilot facts | errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | closed | 0.37 | 0.95 | 0.00 | 1.00 | 0.44 | 0.53 | 0.36 | 0.62 | 0.10 | 0.35 | see json | 0 |
| Qwen3-0.6B-Q4_0 | free | 0.30 | 0.49 | 0.11 | 0.76 | 0.36 | 0.57 | 0.25 | 0.50 | 0.10 | 0.35 | see json | 0 |
| Qwen3-1.7B-Q4_0 | closed | 0.36 | 0.95 | 0.00 | 0.92 | 0.44 | 0.71 | 0.38 | 0.97 | 0.10 | 0.55 | see json | 0 |
| Qwen3-1.7B-Q4_0 | free | 0.40 | 0.71 | 0.16 | 0.60 | 0.40 | 0.70 | 0.36 | 0.92 | 0.25 | 0.55 | see json | 0 |
| Qwen3.5-0.8B-Q4_0 | closed | 0.41 | 0.95 | 0.00 | 0.96 | 0.64 | 0.62 | 0.43 | 1.00 | 0.00 | 0.35 | see json | 0 |
| Qwen3.5-0.8B-Q4_0 | free | 0.00 | 0.01 | 0.00 | 0.84 | 0.00 | 0.09 | 0.00 | 0.18 | 0.05 | 0.35 | see json | 0 |
| Qwen3.5-2B-Q4_0 | closed | 0.47 | 0.94 | 0.01 | 1.00 | 0.48 | 0.64 | 0.51 | 1.00 | 0.50 | 0.65 | see json | 0 |
| Qwen3.5-2B-Q4_0 | free | 0.25 | 0.42 | 0.01 | 0.80 | 0.20 | 0.41 | 0.55 | 0.97 | 0.30 | 0.65 | see json | 0 |
| granite-4.0-h-1b-Q4_0 | closed | 0.49 | 0.97 | 0.00 | 0.92 | 0.56 | 0.72 | 0.53 | 0.78 | 0.05 | 0.35 | see json | 0 |
| granite-4.0-h-1b-Q4_0 | free | 0.33 | 0.42 | 0.06 | 0.80 | 0.36 | 0.47 | 0.40 | 0.50 | 0.05 | 0.35 | see json | 0 |
| granite-4.0-h-350m-Q4_0 | closed | 0.27 | 0.95 | 0.00 | 0.92 | 0.08 | 0.35 | 0.47 | 0.32 | 0.50 | 0.50 | see json | 0 |
| granite-4.0-h-350m-Q4_0 | free | 0.22 | 0.05 | 0.01 | 0.96 | 0.04 | 0.29 | 0.42 | 0.30 | 0.10 | 0.50 | see json | 0 |

| L0 verdict + model explanation (closed) | verdict | citation | halluc. | explanation mention | RO language | injection canary safe |
|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | 0.59 | 0.93 | 0.00 | 0.56 | 0.57 | 1.00 |
| Qwen3-1.7B-Q4_0 | 0.59 | 0.93 | 0.00 | 0.73 | 0.96 | 0.92 |
| Qwen3.5-0.8B-Q4_0 | 0.59 | 0.93 | 0.00 | 0.64 | 1.00 | 0.96 |
| Qwen3.5-2B-Q4_0 | 0.59 | 0.93 | 0.00 | 0.62 | 1.00 | 1.00 |
| granite-4.0-h-1b-Q4_0 | 0.59 | 0.93 | 0.00 | 0.71 | 0.77 | 0.92 |
| granite-4.0-h-350m-Q4_0 | 0.59 | 0.93 | 0.00 | 0.40 | 0.23 | 0.92 |
| (L0 template alone) | 0.59 | 0.93 | 0.00 | 0.27 | - | - |

| model | cached prefix tokens (median) | new prompt tokens / incident (median) | answer tokens / incident (median) | PROJECTED CM5 prefill tok/s | PROJECTED CM5 decode tok/s | PROJECTED s / incident | PROJECTED incidents / min (one stream) |
|---|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | 368 | 168 | 113 | 240 | 30.9 | 4.4 | 13.8 |
| Qwen3-1.7B-Q4_0 | 360 | 175 | 120 | 71 | 11.2 | 13.2 | 4.5 |
| Qwen3.5-0.8B-Q4_0 | 121 | 397 | 93 | 179 | 23.3 | 6.2 | 9.7 |
| Qwen3.5-2B-Q4_0 | 99 | 401 | 76 | 72 | 9.7 | 13.4 | 4.5 |
| granite-4.0-h-1b-Q4_0 | 88 | 418 | 108 | 96 | 13.6 | 12.3 | 4.9 |
| granite-4.0-h-350m-Q4_0 | 113 | 413 | 79 | 421 | 54.6 | 2.4 | 24.7 |
