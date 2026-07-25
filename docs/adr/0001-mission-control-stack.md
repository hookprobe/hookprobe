# ADR 0001 — Mission Control technology stack

**Status:** ✅ Accepted / **locked** (2026-06-27) — `code-developer` vertical slice tunes, it does not reverse, this decision.
**Date:** 2026-06-27
**Deciders:** os-architect, code-developer, ux-architect (UX performance budget)

## Context

Mission Control is two surfaces with opposite optimization targets:
- A **dense, real-time SOC dashboard** (live telemetry, many websocket/SSE-driven widgets, the QSecBit orb, node graphs) that must run on **constrained edge hardware** — Raspberry Pi 5 (arm64, 4–8 GB), RK3588 (arm64, 8–16 GB), Intel N100 (x86, 8–16 GB) — *and* in the cloud.
- A **content-heavy CMS/SEO/docs/blog** surface (the Knowledge workspace) that wants zero-JS and top SEO.

The OS already commits to **Rust + Wasm/WASI** with a strong supply-chain/PQC posture. The starting hypothesis was Astro + React.

## Decision — LOCKED: **Astro + SolidJS + Rust/Axum**

| Layer | Locked choice | Fallback (if a named pressure appears) |
|---|---|---|
| **UI component framework (everywhere)** | **SolidJS** — one component language across both surfaces; JSX (React-adjacent DX); fine-grained signals bound 1:1 to telemetry streams; virtualized grids | **Svelte 5** if Solid's ecosystem/hiring becomes the bottleneck — works in Astro islands too, so only the dashboard island swaps |
| **Content / CMS / SEO surface** | **Astro** hosting **Solid islands** — Astro owns zero-JS content, blog, docs, SEO (the Knowledge workspace); interactivity is Solid islands | — |
| **Live dashboard** | **SolidJS SPA route** (`/app`) served alongside the Astro content surface (`/`) | — |
| **Backend / control API** | **Rust + Axum (Tokio)** — REST + WS control channel + SSE telemetry | Actix (last ~5% throughput); Go only if Rust velocity blocks |
| **Real-time transport** | **SSE over HTTP/2** for one-way telemetry/score fan-out + **one WebSocket** for bidirectional control | WebSocket-only (simpler, accept manual reconnect) |

**One framework, two surfaces:** Astro is framework-agnostic, so "Astro + Solid" is a single-component-language stack — Astro for content/SEO, Solid islands for interactivity, a Solid SPA for the dashboard. Not a forced split between two component frameworks.

WebTransport is **deferred** (server support still experimental in 2026); revisit in ~12 months for mobile/field clients as an HTTP/3 upgrade path.

## Rationale

- **Edge runtime cost dominates, not initial load.** For a high-churn dashboard on a weak ARM core, fine-grained reactivity (Solid signals / Svelte 5 runes) updates only the bound DOM nodes — no VDOM diffing, no re-render cascade, lowest memory. React trails and needs hand-optimization to keep up. The perf gap shows up exactly in our workload (>30fps updates, large grids, limited JS thread).
- **Astro is the wrong tool for the live app** (islands don't fit one big interactive surface with shared state) but the *right* tool for content (zero-JS, SEO). Hence a deliberate hybrid, not one framework forced across both.
- **Rust + Axum aligns the control plane with the OS posture:** ~8.5 MB RSS vs ~82 MB for Node — meaningful on a 4 GB Pi shared with Wasm detection modules; no GC means flat p99 under sustained load; one `cargo`/audit/supply-chain surface; shared types with detection modules; Tokio is purpose-built for cheap WS/SSE fan-out (`broadcast::channel`, one task per connection).
- **SSE/HTTP-2 + WS split:** SSE gives free auto-reconnect and sails through corporate proxies for the high-volume one-way push; a single WS handles genuine duplex control. **SSE requires HTTP/2 end-to-end** to avoid the browser 6-connection-per-domain limit — enforce HTTP/2 at the edge proxy.

## Forward-thinking & quantum-readiness

The framework choice is crypto-neutral on its own — **quantum-readiness is delivered at the crypto/transport layer, not the UI layer** — but this stack is the *most* PQC-forward option available, and it serves the manifest's existing crypto posture (`tls_kex: ml-kem-768+x25519`, `image_signing: ml-dsa-65`) directly:

- **Rust is the strongest PQC ecosystem for a control plane.** `rustls` already ships the hybrid **X25519MLKEM768** key exchange (NIST/IETF hybrid PQC), and RustCrypto / `aws-lc-rs` provide ML-KEM (FIPS 203) and ML-DSA (FIPS 204). Axum runs on `hyper` + `tokio-rustls`, so the dashboard's HTTPS/HTTP-2, SSE, and WebSocket channels inherit **hybrid post-quantum TLS** natively — no bolt-on. Node/Go lag here.
- **Browsers already negotiate it.** Chrome and Firefox ship X25519MLKEM768; because Astro/Solid speak plain HTTPS, the PQC hybrid is negotiated at the TLS handshake transparently — the frontend needs no change to be quantum-safe in transit.
- **Crypto-agility, not a hard-coded algorithm.** Keep TLS/signing behind the agility interface the OS already mandates (algorithms are a policy choice in the manifest + CBOM), so swapping ML-KEM/ML-DSA parameter sets — or adding a future PQC primitive — is config, not a re-architecture. This tracks NSA CNSA 2.0 (PQC for new acquisitions 2027; firmware-signing PQC-exclusive Jan 1 2027) without re-platforming.
- **Enforce HTTP/2 with hybrid KEX at the edge proxy / Axum TLS** — this is the same HTTP/2 requirement SSE already imposes, so the PQC posture and the transport decision reinforce each other (and leave a clean path to HTTP/3 + WebTransport later).

**Net:** locking Rust/Axum is itself the forward-thinking, quantum-ready choice for the backend; Astro/Solid stay quantum-safe for free because PQC lives in the TLS layer beneath them.

## Consequences / risks

- **Solid ecosystem** is smaller (fewer turnkey component *kits*, smaller hiring pool). Mitigation: the primitives we lean on hardest are **framework-agnostic** — charting (uPlot/ECharts/D3), code/query editors (CodeMirror), rich-text (ProseMirror/TipTap core) — so they wrap thinly in Solid; JSX keeps DX React-adjacent; Svelte 5 is the escape hatch (dashboard island only).
- **Knowledge-workspace editors** (Page Generator, AI Writer, Video Generator) are where ready-made React components are most missed. Mitigation/action: `code-developer` validates these against the agnostic editor cores (ProseMirror/TipTap, CodeMirror) **early** so the content surface isn't the thing that forces a framework rethink.
- **Rust velocity** is slower than Go/Node. Mitigation: it's already the house language; Axum ergonomics are good; the PQC/supply-chain payoff is decisive.
- **SSE needs HTTP/2** or it hits the connection wall. Mitigation: enforce at the proxy — same HTTP/2 the hybrid-PQC TLS wants (free path to HTTP/3 + WebTransport later).

## Validation (tuning, not reversal)

The decision is locked. `code-developer` builds a thin vertical slice — Solid dashboard panel ← SSE/WS ← Axum over **hybrid-PQC TLS (X25519MLKEM768)**, deployed on a Pi 5 and an N100 — to measure bundle size, TTI, memory, and live-update latency against the UX performance budget, and to confirm the agnostic editor cores cover the Knowledge-workspace surfaces. Findings tune defaults (e.g. virtualization thresholds), they don't reopen the stack choice.

## Sources

js-framework-benchmark (krausest); PkgPulse "Solid vs Svelte 5 vs React reactivity 2026"; Leapcell signals-vs-runes; Astro islands docs + "Stateful Island Paradox"; Astro Solid integration (`@astrojs/solid-js`); Sharkbench Axum; DevPro Node/Go/Rust 2025; websocket.org Rust guide; Rustify Axum realtime 2026; Aptuz & RxDB & Ably transport comparisons; MDN SSE; Chromium 6-connection bug; portalZINE SSE 2025. **PQC:** rustls hybrid X25519MLKEM768 support; RustCrypto ml-kem / ml-dsa crates; aws-lc-rs FIPS PQC; NIST FIPS 203/204; NSA CNSA 2.0 timeline; Chrome/Firefox X25519MLKEM768 rollout.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The dashboard survives; Astro/Solid is substrate-independent, but the Axum/Tokio/hyper/rustls backend needs a std-or-shim runtime on heqk — or (the planned path) it runs in the Zone-4 monitored Linux guest / a hosted control node while heqk is the sensor. → **Phase M6** in `docs/MIGRATION-heqk.md`.
