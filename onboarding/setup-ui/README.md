# onboarding/setup-ui — first sign-in to Mission Control

heqk serves Mission Control **from the device** (ADR 0047): browser → device, with no Linux in
the path. Each factory image ships with its own owner key (`<image>.owner-key`, mode 600, the only
copy). The device stores only a salted verifier of it.

| What | Where |
|---|---|
| The UI (Astro + SolidJS) | [`os/mission-control/`](../../os/mission-control/) |
| HTTP server, sign-in and state | [`mcserve.rs`](../../os/kernel/kernel/src/mcserve.rs), [`http.rs`](../../os/kernel/kernel/src/http.rs), [`mcauth.rs`](../../os/kernel/kernel/src/mcauth.rs), [`mcstate.rs`](../../os/kernel/kernel/src/mcstate.rs) |
| HTTPS | [`tlshost.rs`](../../os/kernel/kernel/src/tlshost.rs), ADR 0051 |
| End-to-end test (QEMU + real browser) | [`mc-e2e.sh`](../../os/kernel/tools/mc-e2e.sh) · metal: [`mc-e2e-metal.sh`](../../os/kernel/tools/mc-e2e-metal.sh) |
| UX spec | [MissionControl.md](../../docs/architecture/MissionControl.md) |
