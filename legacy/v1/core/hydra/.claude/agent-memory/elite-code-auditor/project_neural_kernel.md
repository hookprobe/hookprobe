---
name: neural_kernel_review
description: Key bugs and patterns found in the Neural-Kernel implementation (cognitive_defense.py, risk_velocity.py, predictor_engine.py, semantic_tokenizer.mojo, meta_regression.mojo)
type: project
---

Reviewed 2026-03-15. Neural-Kernel = risk_velocity + cognitive_defense + predictor_engine Phase 4+5.

**Why:** New autonomous defense system written in one session — reviewed before deployment.

**How to apply:** When touching these files, check for these known issues and patterns.

## Critical Findings (some unfixed as of review date)

### SQL Injection Pattern
- NO `_safe_ip()` validator exists in either cognitive_defense.py or risk_velocity.py
- Every `IPv4StringToNum('{ip}')` interpolation is unvalidated
- Worst path: `_record_lesson()` in cognitive_defense.py line 515 — ip comes from operator-controlled DB field
- Fix: add `ipaddress.ip_address()` validation wrapper before all SQL interpolation
- Same issue in feed_sync.py line 426 in `sync_cognitive_blocks()`

### 16-bit Token Overflow (CRIT)
- `semantic_tokenizer.mojo` to_composite() shifts flow_shape (3 bits, max=7) left 14 → 7<<14 = 0x1C000 = 17 bits
- UInt16 max is 65535 (16 bits) — bit 16 is SILENTLY LOST in Mojo, produces >65535 in Python
- Both risk_velocity.py line 261 and semantic_tokenizer.mojo line 135 have this bug
- `behavioral_tokens.composite_token` schema column is UInt16 — must change to UInt32
- The SQL comment at v3.2-neural-kernel.sql line 79 describes the wrong layout: says 16-bit but needs 17 bits

### scores[-1] Is Not Latest Score
- risk_velocity.py line 368: `'latest_score': scores[-1]`
- ClickHouse `groupArray()` has no defined order — scores[-1] is arbitrary
- Must sort by timestamp first or use `argMax` in query

### _expire_blocks() Logic Bug
- cognitive_defense.py line 781: `del self._active_blocks[ip]` runs even if ch_query() fails
- In-memory expiry clears but ClickHouse row stays auto_expired=0
- feed_sync.py keeps enforcing via sync_cognitive_blocks() indefinitely

### _active_blocks Memory Leak
- No capacity cap — DDoS with 100K unique IPs exhausts container memory
- Also lost on container restart but ClickHouse rows persist → permanent blocks
- Root fix: add `expires_at` column to hydra_blocks, eliminate the in-memory dict

### Dead Code: resp.status == 429
- cognitive_defense.py line 129: `if resp.status == 429: continue`
- urlopen() raises HTTPError for 4xx/5xx BEFORE reaching this check
- This branch is unreachable dead code

## Architecture Gaps
- `behavioral_tokens` table defined in schema but never written to by any pipeline
- `MetaRegressionEngine` in meta_regression.mojo is never called from Python
- `meta_regression.mojo` L4/L7 decomposition is dead code end-to-end
- Mojo tokenizer expects 32 dims, Python pipeline produces 24 dims (mismatch)

## Known-Good Patterns
- OLS uses centered values for numerical stability (correct)
- LLM API key never logged (only response length logged)
- KNOWN_GOOD guard in ReflexArc.should_reflex() prevents CDN false positives
- Trusted CIDR check uses ipaddress.ip_network.overlaps() (not string prefix)
- ClickHouse INSERT uses POST body for VALUES (correct per prior learning)
