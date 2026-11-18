| model | mode | verdict | citation | halluc. entities/case | injection canary safe | injection verdict | explanation mention | RO verdict | RO language | insufficient-evidence calibrated | tool | copilot facts | errors |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | closed | 0.44 | 1.00 | 0.00 | 1.00 | 0.67 | 0.70 | 0.00 | 1.00 | 0.00 | 0.20 | see json | 0 |
| Qwen3-0.6B-Q4_0 | free | 0.50 | 0.06 | 0.12 | 0.67 | 0.67 | 0.95 | 0.25 | 1.00 | 0.00 | 0.20 | see json | 0 |
| Qwen3-1.7B-Q4_0 | closed | 0.75 | 1.00 | 0.00 | 0.67 | 1.00 | 0.85 | 0.75 | 1.00 | 0.50 | 0.80 | see json | 0 |
| Qwen3-1.7B-Q4_0 | free | 0.81 | 0.56 | 0.25 | 0.67 | 1.00 | 0.80 | 0.75 | 1.00 | 0.50 | 0.80 | see json | 0 |
| Qwen3.5-0.8B-Q4_0 | closed | 0.62 | 1.00 | 0.00 | 1.00 | 0.67 | 0.70 | 0.75 | 1.00 | 0.00 | 0.40 | see json | 0 |
| Qwen3.5-0.8B-Q4_0 | free | 0.00 | 0.00 | 0.00 | 1.00 | 0.00 | 0.20 | 0.00 | 0.20 | 0.00 | 0.40 | see json | 0 |
| Qwen3.5-2B-Q4_0 | closed | 0.69 | 1.00 | 0.00 | 1.00 | 0.67 | 0.90 | 0.75 | 1.00 | 0.50 | 0.60 | see json | 0 |
| Qwen3.5-2B-Q4_0 | free | 0.19 | 0.25 | 0.00 | 1.00 | 0.00 | 0.45 | 0.75 | 1.00 | 0.00 | 0.60 | see json | 0 |
| granite-4.0-h-1b-Q4_0 | closed | 0.69 | 1.00 | 0.00 | 1.00 | 0.33 | 0.95 | 0.50 | 1.00 | 0.00 | 0.60 | see json | 0 |
| granite-4.0-h-1b-Q4_0 | free | 0.50 | 0.25 | 0.06 | 0.67 | 0.00 | 0.85 | 0.50 | 1.00 | 0.00 | 0.60 | see json | 0 |
| granite-4.0-h-350m-Q4_0 | closed | 0.25 | 1.00 | 0.00 | 1.00 | 0.00 | 0.40 | 0.50 | 1.00 | 1.00 | 0.40 | see json | 0 |
| granite-4.0-h-350m-Q4_0 | free | 0.25 | 0.00 | 0.00 | 1.00 | 0.00 | 0.30 | 0.50 | 0.40 | 0.00 | 0.40 | see json | 0 |

| L0 verdict + model explanation (closed) | verdict | citation | halluc. | explanation mention | RO language | injection canary safe |
|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | 1.00 | 1.00 | 0.00 | 0.74 | 1.00 | 1.00 |
| Qwen3-1.7B-Q4_0 | 1.00 | 1.00 | 0.00 | 0.89 | 1.00 | 0.67 |
| Qwen3.5-0.8B-Q4_0 | 1.00 | 1.00 | 0.00 | 0.68 | 1.00 | 1.00 |
| Qwen3.5-2B-Q4_0 | 1.00 | 1.00 | 0.00 | 0.89 | 1.00 | 1.00 |
| granite-4.0-h-1b-Q4_0 | 1.00 | 1.00 | 0.00 | 0.95 | 1.00 | 1.00 |
| granite-4.0-h-350m-Q4_0 | 1.00 | 1.00 | 0.00 | 0.47 | 1.00 | 1.00 |
| (L0 template alone) | 1.00 | 1.00 | 0.00 | 0.68 | - | - |

| model | cached prefix tokens (median) | new prompt tokens / incident (median) | answer tokens / incident (median) | PROJECTED CM5 prefill tok/s | PROJECTED CM5 decode tok/s | PROJECTED s / incident | PROJECTED incidents / min (one stream) |
|---|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | 304 | 167 | 138 | 240 | 30.9 | 5.2 | 11.6 |
| Qwen3-1.7B-Q4_0 | 356 | 134 | 125 | 71 | 11.2 | 13.1 | 4.6 |
| Qwen3.5-0.8B-Q4_0 | 63 | 434 | 93 | 179 | 23.3 | 6.4 | 9.3 |
| Qwen3.5-2B-Q4_0 | 63 | 434 | 65 | 72 | 9.7 | 12.8 | 4.7 |
| granite-4.0-h-1b-Q4_0 | 19 | 445 | 98 | 96 | 13.6 | 11.9 | 5.1 |
| granite-4.0-h-350m-Q4_0 | 19 | 445 | 82 | 421 | 54.6 | 2.6 | 23.5 |
