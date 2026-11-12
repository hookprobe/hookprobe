# HEQK Native Management Shell (`hsh`): architecture, command reference and implementation guide

**Component:** `hsh`, the HEQK native management shell.
**Target:** Raspberry Pi CM5, AArch64, Rust `no_std`.
**Runs at:** EL0. **Management authority:** `cfgd` (EL1).
**Status:** Implementation specification (operator, 2026-11-10). It is MVP step 4 of ADR 0059's confirmed
build order: Phase 0 → HQCFG1 → cfgd → management ABI + `hsh` at EL0.
**Related:** ADR 0050 (parser placement), ADR 0056 (upload), ADR 0058, ADR 0059 (D9), and
`docs/design/secure-config-assessment-2026-11-10.md` §B.8 / Phase 5.

---

## 0. Reconciliation with the repository (read first)

The operator's specification (§1 onward) was checked against the code on 2026-11-10 (`feat/heqk-prod-phases`).
Where this section and the body disagree, **this section wins**. Each item is labelled [VERIFIED] (seen in the
code), [DESIGN] (a recommendation) or [DECISION] (needs the operator).

| # | Body says | Repository reality | Resolution |
|---|---|---|---|
| R1 | `hsh` is a "low-priority EL0 component" | [VERIFIED] heqk EL0 components are **bounded excursions**, not processes. `el0-tlshost` "runs ONE command from the shared IO region (`hal::tlsabi`) and exits back to the kernel with `SYS_EXIT_USER`"; state lives in statics between excursions. There is no scheduler and no process priority. | [DESIGN] `hsh` is a new `os/kernel/el0-hsh/` excursion server with an `hal::hshabi` IO region. **Two-phase per command:** (1) the kernel passes one input line in; `hsh` returns either output text or one bounded `MgmtRequest`; (2) the kernel dispatches the request through `mgmtabi` (EL1) and re-enters `hsh` with the `MgmtReply`; `hsh` formats it. The excursion budget bounds execution time. A fault kills only the shell session (ADR 0050 D5). |
| R2 | Interfaces `wan0`, `lan0`, `mgmt0`, `wlan0` | [VERIFIED] The kernel model is `hal::policy::If` = `Lan`, `Eth1`, `Wan`, `Mgmt` (`IF_N = 4`). Physically, `end0` is the RP1 GEM WAN and `eth1` is the RTL8111H LAN. | [DESIGN] Use the existing names (`wan`, `lan`, `eth1`, `mgmt`) and add **no aliases**: "do not introduce a parallel interface model" (§4.2). The Wi-Fi AP is reported under whatever `If` the kernel binds it to. |
| R3 | Read-only commands "use existing inspection APIs" | [VERIFIED] Mission Control's read state comes from kernel producers behind `GET /api/*`. Examples: `/api/qsecbit`, `/api/capabilities`, `/api/dns`, `/api/devices`, `/api/detections`, `/api/incidents`, `/api/tls`, `/api/anchor`, `/api/upload`, and the network state behind `/api/network`. QSECBIT exists (`snapshot.rs`, `packet.rs`). | [DESIGN] `mgmtabi` `GET_*` messages are served by **those same producers**, returned as bounded fixed-layout structs (not JSON). This gives one data model, and Mission Control and `hsh` see identical numbers. Over time the HTTP JSON is formatted from the same structs. |
| R4 | `config stage /management/new-config.hqcfg` | [VERIFIED] EL0 has no filesystem. Bundles reach the device through the ADR 0056 upload flow (`/api/upload/begin`/`chunk`/`finish` into the DataVolume Staging region). | [DESIGN] `config stage <upload-id>` stages a bundle that has already been uploaded and verified, by its handle. On a development UART build only: `config stage paste` reads base64 lines into a bounded 16 KiB buffer. No path syntax. |
| R5 | Stage 1–2 (foundation + read-only) before Stage 3 (ABI) | Stage 2 itself requires "bounded management messages", so the ABI cannot come after it. | [DESIGN] Merge: **4a** = `mgmtabi` read messages + `hsh` foundation + read-only commands. **4b** = configuration commands (only after cfgd, MVP step 3). **4c** = owner commands. `owner status`/`enroll`/`rotate` can map to the backend that already exists (`/api/anchor*`, ADR 0058 (p1e)). `delegate`/`revoke`/`recovery` stay "not supported" until their backends exist (§7 already says so). |
| R6 | UART RX off in production (`console-in`) | Then a production device has **no `hsh` transport at all**. | **[DECISION]** Choose one: (a) `hsh` in production only as a Mission Control web console over the authenticated TLS session, with UART RX off; (b) (a) plus UART RX enabled in production at `view` role only, with elevation by `K_own` challenge; (c) UART only, development builds only. **Recommended: (b).** Anyone at the UART already has physical access, the view role exposes no secrets, and an on-site technician gets a console without a laptop on the LAN. Changing ADR 0059 D9 needs the operator's word. **Decision 2026-11-12 (operator): R6 = D** — owner-key-signed command envelopes (HQMGMT1); the carrier carries no authority. Built: the web carrier `POST /api/hsh` (feature `hsh`, in the AP product) runs view commands on the owner session; every privileged command, from any client, needs an envelope signed off-device by `K_own` and bound to the device, the boot epoch, a fresh sequence and (confirm / rollback) the bundle in force. Session elevation (`owner elevate`) is retired. No UART carrier is built. Options and test criteria: `docs/design/hsh-r6-transport-options.md`. |
| R7 | Audit "timestamp" | [VERIFIED] The device has no trusted RTC. Time comes from SNTP (`mcstate::sntp_parse_strict`). | [DESIGN] Journal records carry the monotonic sequence number, plus SNTP time flagged `synced`/`unsynced`. |
| R8 | Physical presence: "setup button or three power cycles" | [ASSUMPTION] It is unverified whether the CM5 carrier has a usable setup button (ADR 0059 open item 1). | `recovery *` commands wait for that decision. |
| R9 | `reboot` | [VERIFIED] `/api/reboot` exists, with owner re-authentication. | It becomes the `REBOOT` message, with the same authorization. |
| R10 | Capability labels `SYS_READ` … `RECOVERY` | ADR 0059 D9 roles: `view`, `operate`, `config:<scopes>`, `owner`, `recovery`. | Map: `*_READ` → view; `CFG_CONFIRM`, `CFG_ROLLBACK` → operate; `CFG_STAGE` → config; `OWNER_ADMIN` → owner; `RECOVERY` → recovery. cfgd enforces roles. The shell only hides commands for the user's convenience. |
| R11 | `hsh` heap | [VERIFIED] `el0-tlshost` uses a `talc` heap. | `hsh` needs none. The parser **and** the formatter use fixed buffers. |

---

# 1. Purpose

`hsh` is the native command-line management environment for HEQK.

It gives operators a small, deterministic, security-conscious interface for inspecting, diagnosing and managing
the device.

It is not Bash, BusyBox, a Linux shell or a general-purpose scripting environment.

Its purpose is to expose HEQK capabilities through a consistent management interface without giving interactive
users direct access to kernel internals.

```text
                  MANAGEMENT CLIENTS
       ┌──────────────┬──────────────┬──────────────┐
       │     hsh      │ Mission      │ AI Copilot   │
       │   EL0        │ Control UI   │ Tool Layer   │
       └──────┬───────┴──────┬───────┴──────┬───────┘
              └──────────────┼──────────────┘
                     Management ABI
                  ┌──────────▼──────────┐
                  │   cfgd (EL1)        │
                  │ single config writer│
                  │ authn · authz ·     │
                  │ validation · staging│
                  │ trial/commit ·      │
                  │ rollback · journal  │
                  └──────────┬─────────┘
                    Validated policy
             ┌───────────────┼────────────────┐
          Network         Security         Storage
```

**One management API. One configuration authority. Multiple management clients.** `hsh`, Mission Control and
future AI integrations must not implement separate configuration authorities.

# 2. Architectural principles

## 2.1 EL0 isolation
`hsh` runs at EL0 (as a bounded excursion; see R1). It parses untrusted user input and talks to the kernel through
a bounded management ABI, consistent with ADR 0050.

The shell must not:
- access kernel memory directly;
- modify networking structures;
- write directly to configuration storage;
- change security policy on its own;
- bypass signature verification of configuration;
- invoke arbitrary kernel functions;
- execute arbitrary machine code.

An invalid command or a parser fault must not compromise packet forwarding.

## 2.2 cfgd is the single writer
`cfgd` (EL1) owns the configuration lifecycle:
- configuration state;
- owner-key verification and signature validation;
- authorization;
- schema validation and capability checks;
- staging, trial activation, health monitoring, commit and rollback;
- security audit records.

`hsh` sends requests and displays results. It never decides on its own whether a configuration is trusted.

## 2.3 Minimal runtime
- Rust `no_std`.
- Fixed-size input buffers and bounded tokenization.
- A static command registry.
- No dynamic allocation.
- No external dependencies.
- No process execution and no background tasks.
- Deterministic command execution.

Do not introduce a terminal framework or a large argument-parsing dependency.

# 3. Command-line experience

```text
HEQK Management Environment
HookProbe HEQK v0.x
Platform: Raspberry Pi CM5
Security: CONFIG PROTECTED
Management: READ-ONLY

heqk>
```

Typical first commands: `help`, `info`, `uptime`, `interface list`, `ip address`, `route show`, `vlan show`,
`firewall status`.

Commands use consistent naming and predictable output. Every example value in this document is illustrative, not
device state. Interface names follow R2.

# 4. Command namespaces

## 4.1 System
| Command | Description |
|---|---|
| `help` | Available commands (only those this build and role support) |
| `version` | HEQK version and build |
| `info` | Hardware and platform information |
| `uptime` | Uptime |
| `memory show` | Memory statistics |
| `cpu show` | CPU information |
| `boot status` | Verified-boot status (slot, SVN, HBoot result) |
| `security status` | Overall security posture |
| `reboot` | Authorized reboot request (R9) |

`info` shows: platform, architecture, kernel, execution levels, memory, boot slot, configuration state, owner key
(ENROLLED or NONE) and management state. It never prints key material.

## 4.2 Interfaces
| Command | Description |
|---|---|
| `interface list` | List interfaces |
| `interface show <if>` | State, link, MAC, MTU, IPv4/IPv6, gateway, VLAN, RX/TX packets and errors |
| `interface stats <if>` | Counters |
| `interface status` | Aggregate link state |

Use the existing interface inspection producers (R3). Do not create a parallel interface model (R2).

## 4.3 IP
`ip address`, `ip route`, `ip neighbor`, `ip stats`.

IPv6 output includes the prefix length and the address state.

## 4.4 Routing
`route show [ipv4|ipv6]`, `route stats`.

**Route changes are never a shell operation of their own.** They go through the authenticated configuration
lifecycle.

## 4.5 VLAN and QinQ
`vlan show`, `vlan status`, `vlan stats`, `vlan qinq`.

Configured state and operational state are reported separately.

## 4.6 PPPoE
`pppoe status` (state, authentication method, local and peer address, MTU, session uptime), `pppoe stats`,
`pppoe diagnostics` (PADI/PADO/PADR/PADS and LCP counters, which the kernel already keeps).

**Never display the PPPoE password. There is no interactive way to change it.** Credentials belong in the signed
bundle.

## 4.7 DHCP and DNS
`dhcp status`, `dhcp leases`, `dns status`, `dns stats`.

Expose only what the underlying subsystem actually supports.

## 4.8 Security and policy
`firewall status`, `firewall stats`, `acl show`, `prefix show`, `qsecbit status`, `security posture`,
`audit status`, `audit recent`.

These commands never expose private keys, authentication tokens or secret configuration values.

# 5. Configuration management (ADR 0059, HQCFG1)

The shell is a management client, not a signer. `K_own` stays off-device.

## 5.1 Commands
| Command | Function |
|---|---|
| `config status` | Lifecycle state: format, active slot, generation and previous generation, state, owner key, signature, device binding, rollback floor |
| `config show` | Active configuration with secrets redacted |
| `config digest` | Digest of the active configuration |
| `config inspect <upload-id>` | Bundle metadata |
| `config stage <upload-id>` | Request staging of an already-signed bundle (R4) |
| `config verify <upload-id>` | Request verification and validation without staging |
| `config confirm` | Confirm a PENDING trial |
| `config rollback` | Request rollback |
| `config history` | Configuration generations |

Every command maps to exactly one `mgmtabi` message.

## 5.2 Lifecycle
1. The owner creates the configuration and signs it off-device, producing an HQCFG1 bundle.
2. The bundle is uploaded (ADR 0056), then staged through `hsh` or the UI over the management ABI.
3. cfgd checks the signature, key and scope.
4. cfgd validates the schema and policy, and checks management reachability.
5. cfgd writes the inactive A/B half.
6. The bundle becomes PENDING and the health window runs.
7. On PASS: COMMIT and raise the floor. On FAIL or timeout: REVERT to the last known good half.

A reboot while PENDING counts as one trial. A second such boot reverts.

## 5.3 Staging output
```text
Configuration staging requested.
Bundle:  Generation 13 · Digest … · Signer OWNER
Result:  Signature VALID · Scope VALID · Device MATCH · Schema VALID
State:   STAGED
```

## 5.4 Confirm and rollback
- `config confirm` never bypasses a health or authorization check.
- `config rollback` asks cfgd. It never rewrites storage and never lowers a generation floor.
- Both display the active and previous generation, the reason, and the resulting state.

# 6. Owner authorization and security

- **6.1** The device holds no owner private key. `hsh` stages signed bundles or shows a draft digest for the owner
  to sign off-device. It cannot authorize a configuration itself.
- **6.2** A session decides whether the device accepts a *request*. The signed bundle decides whether the
  *configuration* is authorized. A session alone never authorizes configuration.
- **6.3 UART:**
  - RX sits behind the `console-in` feature (production policy: see R6).
  - Elevation uses a challenge signed by `K_own`: `HQCHAL1 ‖ device_id ‖ nonce`. Nonces are single-use and
    time-bounded, so a replayed challenge is refused.
  - A UART connection never grants administrative rights by itself.
- **6.4 Capabilities:** the labels map to cfgd roles as in R10. cfgd enforces them.

# 7. Owner and recovery operations

The ADR 0059 ABI operations are: `state`, `stage`, `confirm`, `rollback`, `enroll`, `rotate`, `delegate`,
`revoke`, `challenge`, `recovery`.

The CLI shows a command only once its backend exists:
- `owner status|enroll|rotate`: backend exists (ADR 0058).
- `owner delegate|revoke`: not built yet.
- `recovery status|enter|reset`: wait for the physical-presence decision (R8).

Ownership operations need the matching owner signature or physical-presence recovery. Every one is journaled.

# 8. Diagnostics

`diagnostics summary|network|security|storage|boot|config`.

`diagnostics summary` shows boot verification, kernel state, configuration, WAN/LAN, management, firewall, owner
authorization and journal health, plus warning and error counts.

Diagnostics are bounded and never block the forwarding path.

# 9. Command parser

## 9.1 Limits
These are initial targets, to be validated against the real command set:

| Parameter | Target |
|---|---:|
| Input buffer | 256 B |
| Maximum tokens | 12 |
| Maximum token length | 64 B |
| Maximum command length | 255 B |
| Nesting | 0 |
| Heap | 0 |

## 9.2 Grammar
`command := token (SP token)*`, where `token := printable ASCII 0x21–0x7E +`.

The parser rejects: NUL, control characters, too many tokens, oversized tokens, non-ASCII, and any quoting or
escape syntax. Quoting may be added later, but only if a real use case appears.

## 9.3 Not supported, ever
Pipes, redirection, chaining (`;`, `&&`, `||`), background execution, environment expansion, command substitution,
wildcards, scripts, and loading executables.

# 10. Output

Output is deterministic, human-readable, bounded, and fits both a serial terminal and the web console.

Error categories:
- `ERROR: Unknown command.`
- `ERROR: Invalid argument.`
- `ERROR: Permission denied.`
- `ERROR: Management service unavailable.`
- `ERROR: Configuration signature invalid.`
- `ERROR: Configuration rejected.`
- `ERROR: Operation not supported.`

The output distinguishes four outcomes: command accepted, operation requested, operation completed, operation
refused. **Never print success before the ABI reply confirms it.**

# 11. Audit

cfgd records every privileged operation, including refused ones, in the HMAC-chained owner journal. Each record
holds: operation, requesting identity or role, authorization result, generation, bundle digest, sequence number
plus SNTP time (R7), result and reason.

`hsh` keeps no journal of its own.

# 12. Resources
- No work in interrupt context and nothing that blocks packet processing.
- Bounded execution (the excursion budget) and bounded output.
- No recursion and no allocation.
- No MMIO.
- No duplicated cryptography: signatures are verified only in cfgd.

Binary size is **measured** from the built artifact and never estimated.

# 13. Layout

`os/kernel/el0-hsh/`, containing `parser.rs`, `registry.rs`, `output.rs`, `session.rs` and `commands/*.rs`.

The kernel side adds `os/kernel/kernel/src/mgmtabi.rs` and an `hal::hshabi` IO region. Follow the
`el0-tlshost` / `el0-lansvc` build and loader conventions (R1); they take precedence over this suggested tree.

# 14. Management ABI

The ABI has explicit message IDs, fixed layouts, bounded payloads, a version field, strict validation, capability
checks and explicit result codes.

| Family | Messages |
|---|---|
| System | `GET_INFO`, `GET_UPTIME`, `GET_MEMORY`, `REBOOT` |
| Network | `GET_INTERFACES`, `GET_ROUTES`, `GET_VLAN`, `GET_PPPOE`, `GET_DHCP`, `GET_DNS` |
| Security | `GET_POSTURE`, `GET_ACL`, `GET_PREFIX`, `GET_STATS`, `GET_QSECBIT` |
| Configuration | `STATE`, `STAGE`, `VERIFY`, `CONFIRM`, `ROLLBACK`, `HISTORY` |
| Ownership | `ENROLL`, `ROTATE`, `DELEGATE`, `REVOKE` |
| Recovery | `CHALLENGE`, `RECOVERY` |
| Audit | `GET_JOURNAL_STATUS`, `GET_JOURNAL_RECORDS` |

The ABI is defined once, in `mgmtabi.rs`. For equivalent operations, Mission Control and `hsh` must get the same
authorization decision and produce the same journal record.

# 15. Tests

- **Parser:** empty input; whitespace only; unknown command; at the maximum length and one byte over; too many
  tokens; an oversized token; non-ASCII; NUL; control characters; every shell operator in §9.3; fuzzing.
- **Authorization:**
  - a read command at view role;
  - a configuration operation with no session;
  - a session without a valid signed bundle;
  - the wrong role, or a delegated admin out of scope;
  - a replayed or expired challenge;
  - a revoked admin;
  - owner rotation;
  - physical-presence recovery.
- **ABI:**
  - every message;
  - an unknown message ID, a bad length, a malformed payload;
  - an unauthorized request;
  - concurrent requests from Mission Control and `hsh`;
  - timeout;
  - an EL0 fault in the middle of a command, after which the kernel and forwarding continue.
- **Configuration integration:**
  - a valid bundle;
  - an invalid signature, the wrong device, an unknown key, an unsupported schema;
  - a replayed generation;
  - a failed trial and a reboot while PENDING;
  - confirm, and automatic rollback.
- **Production build:**
  - `console-in` policy as decided in R6, and absent UART RX symbols when it is off;
  - no debug command;
  - EL0 isolation;
  - no access to kernel memory.

# 16. Roadmap

This replaces the body's Stages 1–5 (see R5).

**4a: foundation and read-only views.**
- Build: `mgmtabi` read messages; the `el0-hsh` excursion server; the parser and registry; `help`, `version`,
  `info`, `uptime`, and the read-only commands in §4.
- Accept when:
  - the data comes from the same producers as `GET /api/*`;
  - there is no mutation and no duplicate networking logic;
  - `[P-hsh-parser]` and `[P-mgmtabi]` pass in QEMU;
  - an EL0 fault is contained.

**4b: configuration commands** (after cfgd).
- Build: `config *` on the cfgd messages.
- Accept when:
  - no unsigned configuration can become active;
  - `hsh` makes no direct write;
  - trial and rollback work;
  - the journal records match Mission Control's.

**4c: owner and recovery.**
- `owner status|enroll|rotate` on the existing backend.
- `delegate`/`revoke`/`recovery` once their backends exist.
- `CHALLENGE` elevation, with replay refused.

# 17. Definition of done

1. A working EL0 component.
2. A bounded parser.
3. Real read-only commands.
4. A working ABI.
5. Integration with cfgd.
6. Command-level authorization.
7. Audit integration.
8. QEMU validation.
9. CM5 metal validation where applicable.
10. A measured binary footprint.
11. Verification of the production build.
12. Documentation of the commands actually implemented.

The report must label each item: implemented, tested in QEMU, tested on CM5 metal, planned, or unsupported.

# 18. Final rule

`hsh` stays a small, isolated management client. It never becomes a second kernel, a second configuration manager
or an unrestricted privileged shell.

**The kernel owns enforcement. cfgd owns configuration. The owner owns authorization. `hsh` is the operator's
interface.**
