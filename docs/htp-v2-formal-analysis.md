# HTP v2 — Formal Analysis (ProVerif) — §6.2 gate

**Status:** Symbolic model **built and RUN** with ProVerif 2.05 (native Linux binary, built from source on this machine). **All security queries discharged with definite results** (no `cannot be proved`). · **Date:** 2026-06-29 · **Author:** code-developer · **Inputs:** [`docs/htp-v2-handshake.md`](htp-v2-handshake.md) (reviewed/fixed spec, §7+§8 changelogs).

This is the §6.2 / §7 / §8 gate the spec set before HTP v2 goes to final implementation. It models the **IK-equivalent (device ↔ gateway) VPN handshake** in the applied-pi calculus and checks the seven property classes the task requires.

> One-line verdict: **In the symbolic (Dolev-Yao) model, the HTP v2 IK handshake satisfies mutual injective authentication, session-key secrecy, forward secrecy, KCI resistance, UKS/identity-misbinding resistance, downgrade resistance, and — in the hidden-responder variant — responder-identity secrecy. The §7/§8 fixes hold; in particular the Finding-1 two-transcript split makes responder-identity secrecy both *expressible* and *true*, and a negative control proves the proof is genuine.**

---

## 1. Files

| File | What it models |
|---|---|
| [`security/formal/htp_v2_ik.pv`](../security/formal/htp_v2_ik.pv) | IK handshake, **public-gateway** variant. Mutual auth (both directions, injective), session-key secrecy, **forward secrecy** (phase-1 long-term + PSK reveal), **KCI** (adaptive phase-0 guarded key reveal), **UKS**, **downgrade**. |
| [`security/formal/htp_v2_ik_hidden.pv`](../security/formal/htp_v2_ik_hidden.pv) | IK handshake, **hidden-responder** variant (gateway identity encrypted under `k_hs_g2c`). Adds the **responder-identity-secrecy** query (Finding 1), plus mutual auth + key secrecy. |
| [`security/formal/htp_v2_ik_negctrl.pv`](../security/formal/htp_v2_ik_negctrl.pv) | **Negative control**: identical to the hidden variant but the gateway identity is sent in **cleartext**. Responder-identity secrecy is *expected to fail* here — proving the model has teeth. |
| [`security/formal/run.sh`](../security/formal/run.sh) | Runs all three models (`PROVERIF=/path/to/proverif ./run.sh`). |

Two files are used because the compromise scenarios genuinely conflict: the hidden-responder property requires the gateway's public identity to stay secret, which is incompatible with the adaptive *gateway*-key reveal that the KCI test needs in the same run. Splitting keeps each query meaningful. The split is standard practice; the protocol logic is identical across files.

---

## 2. How the protocol is modelled (faithfulness map)

| Spec element (htp-v2-handshake.md) | ProVerif model |
|---|---|
| Ephemeral **X25519** (§2.2, §2.4) | `type G/exponent`, `dhexp`, the standard DH equation `exp(exp(g,x),y)=exp(exp(g,y),x)`. |
| Ephemeral **ML-KEM-768** (§2.2, §2.4) | KEM as encap/decap: `encap(kempk(sk),ss)=ct`, `decap(sk,ct)=ss`. Encapsulator binds a fresh `ss` into the ciphertext; only the decap-key holder recovers it (IND-CCA / FIPS-203 implicit-rejection abstraction — no decap oracle). Ephemeral `dkC` is never output ⇒ FS. |
| **Hybrid shared secret** combiner `ss_dh‖ss_pq[‖PSK]` (§2.4) | `ikm(ss_dh, ss_pq, psk)` — a one-way constructor feeding `extract`. To derive any key the attacker must hold **both** `ss_dh` *and* `ss_pq` (break **both** KEX legs), matching the IETF concatenation combiner. |
| **Hybrid signatures** Ed25519+ML-DSA-65, both verify (§2.3) | One symbolic unforgeable `sign`/`checksign`. Comment in the model: the real impl needs *both* legs; symbolically a single unforgeable signature is the faithful, conservative abstraction (forgery needs the secret key). |
| **Two-transcript split** (§2.4, §8 Finding 1) | `th_ks(...)` packs **only** key-share fields (version, suites, nonces, ephemerals, KEM pubkey+ct) → salts `extract` → all keys. `th_auth_gw`/`th_auth_cl` additionally include the identity bundles and are signed. Keys never depend on an identity. |
| **SIGMA sign + MAC** (§2.3) | Each side signs `ctx ‖ th_auth_*`; each side MACs `ctx_id ‖ own_pub` under `k_mac` (derived from `th_ks`). The MAC binds identity → derived key (UKS/misbinding defence). |
| **Directional handshake keys** `k_hs_c2g`/`k_hs_g2c` (§2.3, §7 Finding 1) | ATTEST encrypted under `k_hs_c2g`; CHALLENGE id-block / ACCEPT under `k_hs_g2c`. Distinct labels via `kdfexp`. |
| **Directional data keys** `k_c2g`/`k_g2c` (§2.4) | Post-handshake secrets sent under each. |
| **ACCEPT key confirmation** (§2.3) | ACCEPT is an AEAD record under `k_hs_g2c`; the gateway decrypting ATTEST is the client's key confirmation. |
| **Downgrade binding** (§2.6) | `version` + `offered` + `selected` are inside `th_ks` (keys) **and** the signed `th_auth` transcripts; the accepted suite is carried in the authentication events. |
| **`node_id` is a handle, not identity** (§2.9 Finding 2) | `pubNode` is attacker-visible and never used in any security decision; authz is purely on the verified `spkey`. |
| **PSK demoted** (§2.7) | `psk` is an extra `ikm` input only; it never authenticates. |
| AAD = frame header on every record (§2.3) | Distinct `aad_*` constants per record type. |

**Attacker model:** full Dolev-Yao on the public channel `c`. Long-term signing keys and the PSK can be revealed (a) adaptively in **phase 0**, guarded by a `Compromise(pk)` event (drives KCI / adaptive corruption), and (b) unconditionally in **phase 1**, after all phase-0 sessions complete (the forward-secrecy test).

---

## 3. Queries and results (exactly as run)

All results below are copied from ProVerif 2.05 output. Reading convention: for secrecy, `not attacker(x) is true` ⇒ **secret** (good); for correspondences, `... is true` ⇒ property **holds**; the two `event(...Done) ==> false is false` results are deliberate **non-vacuity** checks — `is false` means the honest handshake *is* reachable, so none of the proofs are vacuous.

### `htp_v2_ik.pv`

| # | Property | Query (abridged) | Result |
|---|---|---|---|
| 1 | **Mutual auth — gateway authenticates device** (injective) + **KCI (this side)** | `inj GwAcceptClient(pkC,pkG,sid) ⇒ inj ClientRunForGw(pkC,pkG,sid) ∥ Compromise(pkC)` | **true** |
| 2 | **Mutual auth — device authenticates gateway** (injective) + **KCI (other side)** + **downgrade** (accepted `sel` = gateway's `sel`) | `inj ClientAcceptGw(pkG,sid,sel) ⇒ inj GwRunForClient(pkG,sid,sel) ∥ Compromise(pkG)` | **true** |
| 5 | **UKS / identity-misbinding** | `GwAcceptClient(pkC,pkG,sid) ∧ ClientAcceptGw(pkG2,sid,sel) ⇒ pkG=pkG2` | **true** |
| 3/4 | **Session-key secrecy + forward secrecy** (LT keys + PSK revealed in phase 1) | `not attacker(secretC2G)` (phase-1) | **true (secret)** |
| 3/4 | " | `not attacker(secretG2C)` (phase-1) | **true (secret)** |
| — | non-vacuity (client run reachable) | `event(ClientDone) ⇒ false` | **false** (⇒ reachable ✔) |
| — | non-vacuity (gateway run reachable) | `event(GwDone) ⇒ false` | **false** (⇒ reachable ✔) |

How each requested property maps:

- **Mutual authentication (injective, both directions):** #1 and #2. Injective agreement on the session id `sid = th_ks` (which contains fresh nonces ⇒ one-to-one) gives replay-free, matched-session authentication in each direction.
- **Session-key secrecy:** #3/#4 — the data protected by `k_c2g`/`k_g2c` is non-derivable by the attacker.
- **Forward secrecy:** same queries, but the long-term identity keys *and* the PSK are dumped to the attacker in **phase 1** (after the session). The phase-0 session secrets remain secret ⇒ FS holds. (Keys derive only from the ephemeral `ss_dh`/`ss_pq`, which are wiped.)
- **KCI resistance:** the authentication queries carry a `Compromise` disjunct for **only the party being impersonated**. #1 holds even when `pkG` (the gateway) is compromised ⇒ a leaked gateway key cannot be used to impersonate a *device* to the gateway. #2 holds even when `pkC` (the device) is compromised ⇒ a leaked device key cannot be used to impersonate the *gateway* to the device. That is exactly KCI resistance, via the adaptive phase-0 guarded reveal.
- **UKS / identity-misbinding:** #5 — two honest endpoints that end up on the same session id necessarily agree on the gateway identity; combined with #1/#2 this rules out unknown-key-share. The SIGMA MAC under `k_mac` is what binds identity to the derived key.
- **Downgrade resistance:** #2 — the suite/version the client accepts equals the one the gateway committed to; `version`+`offered`+`selected` live inside the signed `th_ks`/`th_auth`, so any in-band tamper changes the transcript and breaks both the MAC and the signatures.

### `htp_v2_ik_hidden.pv`

| # | Property | Query (abridged) | Result |
|---|---|---|---|
| 6 | **Responder-identity secrecy** (Finding 1) | `not attacker(spk(gskG))` | **true (identity hidden)** |
| 1 | Mutual auth — gateway authenticates device (injective) | `inj GwAcceptClient ⇒ inj ClientRunForGw` | **true** |
| 2 | Mutual auth — device authenticates gateway (injective) | `inj ClientAcceptGw ⇒ inj GwRunForClient` | **true** |
| 3/4 | Session-key secrecy | `not attacker(secretC2G/secretG2C)` | **true (secret)** |
| — | non-vacuity | `event(ClientDone/GwDone) ⇒ false` | **false** (⇒ reachable ✔) |

**Responder-identity secrecy** is the property that originally *flagged* Finding 1. Because `k_hs_g2c` derives from `th_ks` (key-share only, no identity), the gateway can encrypt its identity bundle *before* the identity enters any transcript, and the client — holding the ephemeral secrets — re-derives `k_hs_g2c` from the key-share fields alone and decrypts it. The Dolev-Yao attacker, lacking the ephemeral secrets, cannot derive `k_hs_g2c` and so never learns `spk(gskG)`. The proof confirms the two-transcript split removed the circular dependency: identity hiding is now both *implementable* and *secure*.

### `htp_v2_ik_negctrl.pv` (negative control — proves the model isn't vacuously proving secrecy)

| Property | Result | Meaning |
|---|---|---|
| Responder-identity secrecy (gw identity in **cleartext**) | **false** | Attacker **does** learn `spk(gskG)` — identity leaks, as it must when hiding is off. |
| Mutual auth (both), session-key secrecy, non-vacuity | unchanged (true / reachable) | Only the identity-secrecy property flips. |

The single difference between the hidden variant and this control is encryption of the identity block under `k_hs_g2c`. The query flips from **true** to **false** accordingly. This demonstrates the responder-identity-secrecy proof is *genuine* and is delivered precisely by the `k_hs_g2c` encryption that the Finding-1 split enables — not by an artefact of the abstraction.

### Net: does the model confirm the §7/§8 fixes?

Yes, for the symbolic model:

- **§7 Finding 1 (directional handshake keys):** modelled as distinct `k_hs_c2g`/`k_hs_g2c`; all properties hold with them.
- **§7 Finding 4 / §2.6 (version/downgrade):** version+suite bound and signed ⇒ downgrade query holds.
- **§8 Finding 1 (two-transcript split / responder-identity hiding):** **the headline result** — now expressible and **true**, with a negative control proving it load-bearing.
- **§8 Finding 2 (`node_id` is a handle):** modelled as a security-irrelevant public value; auth depends only on verified keys.
- KCI and UKS (called "confirmed sound" in §7/§8) are **proved**, not just argued.

---

## 4. How it was actually run (honest account of install)

ProVerif was **not** pre-installed and there is **no root** on this machine (`apt-get` needs sudo with a password; no package for `proverif` in the mirror; `opam`/`ocaml` are packaged but need root; the official `proverifbin2.05.tar.gz` ships **Windows** PE binaries; `wine` absent; GitHub is network-blocked). It was therefore **built from source without root**:

1. `apt-get download` (no root needed) the OCaml 4.14.1 `.deb` set (`ocaml`, `ocaml-base`, `ocaml-base-nox`, `ocaml-interp`, `libstdlib-ocaml`, `libstdlib-ocaml-dev`, `libcompiler-libs-ocaml-dev`) from the Ubuntu mirror.
2. `dpkg-deb -x` each into a local prefix; export `PATH=$prefix/usr/bin:$PATH` and `OCAMLLIB=$prefix/usr/lib/ocaml`. `ocamlopt.opt` then works (native codegen uses the system `gcc`/`as`/`ld`).
3. Download `proverif2.05.tar.gz` from `bblanche.gitlabpages.inria.fr` and build the core verifier with `./build -nointeract native` (skips the lablgtk2 GUI). Produces a working native `proverif` binary.
4. `proverif <file>.pv` for each model.

Reproduce with `security/formal/run.sh` once any `proverif` ≥ 2.05 is on PATH (`opam install proverif` is the easy route on a machine with OCaml). The models are plain ProVerif 2.05 syntax with no external libraries. Each model verifies in well under a second.

---

## 5. Limitations — what this proof does and does NOT cover

This is a **symbolic / Dolev-Yao** proof. It is strong evidence of structural soundness but is **not** a computational proof. Honest boundaries:

1. **Perfect cryptography assumption.** Hashes are collision-free and one-way *by fiat*; signatures are unforgeable; AEAD is perfect; DH/KEM are idealised. Real-world breaks in any primitive are invisible here.
2. **Hybrid signatures are one symbolic primitive.** The model proves "a forgery needs the secret key." It does **not** reason about the *hybrid* composition itself (e.g., a non-separable/weak-binding combiner, or one leg being forgeable while the other holds). The spec's "both Ed25519 and ML-DSA must verify" is asserted, not analysed. A computational/EUF-CMA argument for the specific concatenation is out of scope.
3. **Hybrid KEM is the standard encap/decap abstraction.** ML-KEM-768 is modelled as an idealised IND-CCA KEM with a freshly-chosen shared secret. It captures implicit rejection and "no decap without the secret key," but not FIPS-203 input-validation (§2.9 Finding 4), re-encryption checks, malleability, or binding properties of the concrete scheme.
4. **The hybrid combiner is modelled as one-way over both inputs.** This captures "must break both legs," but not the precise X-Wing/IETF-combiner security argument (e.g., MAL-BIND-K-CT / key+ciphertext binding) at the computational level.
5. **Scope = the core IK key agreement.** Modelled: HELLO/CHALLENGE/ATTEST/ACCEPT, the key schedule, identities, suite negotiation. **Not modelled:** REKEY v2 and the re-signed re-authentication / PCS bounds (§2.5), the anti-DoS retry cookie and `H(ek_pq)` binding (§2.8/§2.9 Finding 3), handshake fragmentation/reassembly and its DoS bounds (§2.8), data-plane nonce/epoch management (§2.9 Finding 7), tenant binding (§2.9 Finding 8), the software-PUF custody/cloning caveats (§2.9 Finding 5), and the XX/mesh simultaneous-open role assignment (§2.9). PCS in particular is **untested** here.
6. **No quantitative/side-channel/fault coverage.** Timing, power, fault-injection (e.g., the deterministic-ML-DSA fault risk in §2.9 Finding 5), traffic-analysis identity inference, and DoS amplification are all outside a symbolic model.
7. **Responder-identity secrecy is modelled as value-secrecy of the public key**, not full observational-equivalence/unlinkability. `not attacker(spk(gskG))` is a sound *necessary* condition (if the attacker can't even obtain the identity bundle, it can't read it off the wire) and it directly exercises the Finding-1 non-circularity. A stronger statement — the attacker cannot *distinguish* which of two candidate gateways responded — would need a ProVerif biprocess (`choice`/observational equivalence) and is the recommended next step.
8. **Bounded faithfulness of the transcript model.** Transcript hashes are modelled as injective constructors over the exact fielded inputs; this assumes the wire encoding is unambiguous/length-delimited (it is — all fields are `u16`-length-prefixed per §2.3) and collision-free.

### What a Tamarin model would add

- **REKEY + re-authentication and post-compromise security** as a multi-stage, *stateful* protocol with explicit key-evolution — Tamarin's mutable state and `restrictions` express "heals after the next rekey" and the `REAUTH_MAX_AGE` active-attacker bound far more naturally than ProVerif phases.
- **Fine-grained, adaptive compromise** (ephemeral-key reveal, state reveal, per-stage corruption) for eCK/CK-style security, including testing FS/PCS against ephemeral leakage — not just long-term-key reveal.
- **Observational-equivalence / unlinkability** for a stronger responder- and initiator-identity-privacy statement.
- Confidence from a different proof engine (multiset-rewriting + backward search) on the same composition.

A computational proof (CryptoVerif, or a pen-and-paper reduction) would additionally retire limitations 1–4 — in particular giving a real argument for the *hybrid* signature and KEM combiner, which §8 itself calls out as "novel in three dimensions at once."

---

## 6. Recommendation

The symbolic gate is **passed** for the IK core AKE: every requested property holds, the §7/§8 fixes (especially the Finding-1 two-transcript split) are confirmed load-bearing, and a negative control shows the proofs are non-vacuous and genuine. **Before final build**, recommend: (a) a Tamarin model covering **REKEY/re-auth/PCS** and an **observational-equivalence** identity-privacy statement; (b) a computational sanity pass (CryptoVerif or a hand reduction) on the **hybrid-signature** and **hybrid-KEM combiner** composition. Items in §6.2 of the spec beyond the core AKE (DoS cookie params, fragmentation caps, data epochs) are engineering-validation, not AKE-soundness, gates.
