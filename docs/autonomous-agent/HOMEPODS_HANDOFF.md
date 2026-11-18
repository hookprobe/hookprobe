# Handoff to homepods (kernel owner)

Requests from the application side. The agent does not change `os/kernel/**`; each item states
what the UI needs, the evidence, and what the UI does meanwhile. Nothing here is urgent unless
marked.

| ID | Request | Why | Evidence | UI meanwhile |
|---|---|---|---|---|
| HP-01 | Serve `GET /api/exploitability` (or confirm it is out of scope) | Intelligence CVE board can never go live | `os/mission-control/src/store/itlLive.ts:62`; route only in `legacy/linux-tier` | falls back to the IOC tab |
| HP-02 | Enrich `/api/devices`: `mac`, hostname / mDNS name, vendor (OUI), zone/policy, label | Device Map, Zones and inventory show bare IPs | `mcstate.rs:571+` emits `id, ip, mac:null, first_seen, last_seen` | shows IP + "name not reported" |
| HP-03 | Incident payload extension (optional fields): ingress interface/zone, Wasm module name + hash, RFC 9669 BPF rule id, sealed record id + seal status, pcap reference | Explainability drawer "Trigger source" and "Sealed record" | being written up by the other session under `docs/adr/notes/` | "not reported yet" |
| HP-04 | Decide on the planner / AEGIS explain endpoint (`POST /api/planner/incidents/:id/explain`), or confirm the UI should drop it | Copilot + "why AEGIS decided" have no backend; `model` always null | `http.rs:427,698`; `plannerApi.ts:110` | honest "No AI planner configured" |
| HP-05 | `/api/reports?limit`: document the 32 cap or page it | UI asks 200, silently gets 32 | `http.rs:741` | UI says "the 32 most recently active incidents, the most this device lists" on a full page (AB-10) |
| HP-06 | `/api/logout`: add the Origin/CSRF check used on other writes | defence in depth (SF-01) | `http.rs:372` | — |
| HP-07 | Ship decision for `wasmhost` (not in any product flavour) | docs claim signed Wasm detection runs today | `kernel/Cargo.toml:69` | docs to say "not shipped" |
| HP-08 | Captive portal / `setup.hookprobe.local` (ADR 0010) — kernel-side DNS redirect | customer day-0 journey | ADR 0010 status "PORTAL … NOT BUILT" | `/setup` behind owner sign-in |
| HP-09 | Add `host_telemetry` to `capabilities.rs` DENIED with a reason (e.g. "No endpoint agent: this device watches the network, not processes") | `/api/incidents/:id/processes` is always empty by design; the UI keys its wording on this capability | `http.rs:713` comment; `capabilities.rs` lists no such id | UI treats "not granted" as "does not see processes" (AB-09) |
