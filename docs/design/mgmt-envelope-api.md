# Owner-signed management envelopes (HQMGMT1): API for Mission Control

Status: built 2026-11-12 (heqk branches `feat/hsh-prod-transport`, then `feat/hsh-signed-endpoints` for the owner
endpoints below), QEMU self-tests `[P-hsh-web]` / `[P-mgmtabi]` / `[P-upload]`, mc-e2e. Metal: pending. Decision: hsh spec R6 = D (operator, 2026-11-12), hard switch: no compatibility flag.

Audience: the Mission Control UI designer. The device side is done; this page is the contract the UI must follow.

## What changed

These endpoints are authorised **only** by an envelope signed with the owner's configuration key `K_own` (the
Ed25519 key enrolled through `/api/anchor/enroll`):

| Endpoint | msg | Binds |
|---|---|---|
| `POST /api/config/confirm` | 20 | the bundle in force (generation + digest from `/api/config`) |
| `POST /api/config/rollback` | 21 | the bundle in force |
| `POST /api/upload/activate` (every type: packs, `wan` / `wifi` / `policy` / `config`, `os_image`) | 23 | type code + staged generation + staged digest (from `/api/upload/finish`) |
| `POST /api/upload/rollback` | 24 | type code + the generation it rolls back TO |
| `POST /api/factory-reset` | 32 | nothing else (device, boot, sequence) |
| `POST /api/anchor/rotate` | 33 | the current owner key (fingerprint) + the new key (SHA-256) + the rotation generation |

The owner session and the `owner_key` token no longer authorise any of them:

- A request without a valid `envelope` is refused (HTTP 403), even with a correct `owner_key`.
- The `owner_key` field is ignored on these endpoints. Do not send it.
- The device never holds the private key. The browser (or the owner's CLI) signs; the device verifies.

The session, `Origin`, `X-HQ-CSRF`, the per-session `seq` and the write rate limit are unchanged: they gate the
transport only.

The same envelope also authorises the web console (`POST /api/hsh`, see below).

**Not envelopes (by design):** `POST /api/upload/begin` keeps the owner token (it stages only; nothing changes until
`activate`). `POST /api/anchor/enroll` (the first, one-shot enrollment, ADR 0058 D3) keeps the owner token plus the
HQENR1 proof of possession of the new key: no K_own exists yet to sign an envelope. `POST /api/owner-key` rotates the
Mission Control sign-in token itself and keeps re-authentication with the current token.

**Known deviation (operator, 2026-11-12, this round):** `POST /api/reboot`, `POST /api/owner-rules` (and
`/revoke-all`), `POST /api/actions` (kinds that need re-authentication) and the alert-hook endpoint still use
`owner_key` re-authentication. They move to envelopes in a later round; this page will say so when they do.

**Accepted consequence:** with no owner key enrolled (`owner_enrolled: false`), no client can confirm, roll back,
activate, factory-reset or rotate by hand. A trial that waits for a confirm reverts automatically when its window
ends; a trial that does not need a confirm still commits on its own when healthy. Enroll an owner key first.

## Step 1: read what to bind

`GET /api/config` (owner session) now carries an additive `envelope` object:

```json
"envelope": {
  "format": "HQMGMT1",
  "device_id": "<32 hex>",
  "epoch": "<16 hex>",
  "next_seq": 1,
  "generation": 12,
  "digest": "<64 hex>",
  "owner_enrolled": true
}
```

| Field | Meaning |
|---|---|
| `device_id` | This device's 16-byte configuration id (the same as `/api/anchor` `device_id`; zeros on a device without one). |
| `epoch` | 8 random bytes drawn once per boot. An envelope signed for an earlier boot is refused. |
| `next_seq` | The lowest sequence number the next envelope may use. Each accepted envelope consumes its number. |
| `generation` | The generation of the configuration bundle in force (on trial or committed); 0 = none. |
| `digest` | SHA-256 of that HQCFG1 bundle (the exact file staged with upload type `config`); 64 zeros = none. |
| `owner_enrolled` | `false`: no owner key is enrolled, so nothing can confirm or roll back by hand. Show "enroll your owner key first" and do not offer the buttons. |

Read this object immediately before signing. If anything is on trial, show the generation and (ideally) compare
`digest` with the SHA-256 of the bundle file the owner staged, so the owner confirms exactly what they staged.

## Step 2: build the envelope (156 bytes, little-endian)

| Offset | Length | Field | Value |
|---|---|---|---|
| 0 | 8 | magic | ASCII `HQMGMT1` followed by one zero byte |
| 8 | 2 | version | `1` (u16 LE) |
| 10 | 2 | msg | u16 LE: `20` confirm, `21` rollback, `23` upload activate, `24` upload rollback, `32` factory reset, `33` anchor rotate (`22` = stage, shell only) |
| 12 | 16 | device_id | from `envelope.device_id` |
| 28 | 8 | epoch | from `envelope.epoch` |
| 36 | 8 | seq | u64 LE, at least `envelope.next_seq` |
| 44 | 8 | arg | u64 LE: `0` for confirm / rollback / factory reset; the **type code** for upload activate / rollback; the **current key fingerprint** for rotate |
| 52 | 8 | generation | u64 LE: confirm / rollback `envelope.generation`; activate the staged `generation`; upload rollback the generation to roll back TO (`GET /api/upload` `types[].rollback_to`); rotate the rotation `generation`; factory reset `0` |
| 60 | 32 | digest | confirm / rollback `envelope.digest`; activate the staged `digest`; rotate SHA-256 of the new public key (32 raw bytes); upload rollback and factory reset all zeros |
| 92 | 64 | signature | Ed25519 by `K_own` over the ASCII bytes `HQMGMT1-SIG` (11 bytes, no terminator) followed by bytes 0..92 |

Type codes: `shield_block` 0, `shield_allow` 1, `ioc` 2, `rules` 3, `oui` 4, `devices` 5, `wan` 6, `wifi` 7,
`policy` 8, `config` 9, `os_image` 254. Key fingerprint (rotate `arg`): the first 8 bytes of SHA-256 of the current
owner public key (`/api/anchor` `owner_key`, 32 raw bytes), read as a little-endian u64.

`device_id`, `epoch` and `next_seq` always come from `GET /api/config` `envelope`, read just before signing.

Encode the 156 bytes as 312 hex digits (lower or upper case).

Browser sketch (WebCrypto Ed25519; the key is the owner's enrolled key, for example unwrapped from the
passphrase-protected backup Mission Control already handles):

```js
const hex = s => Uint8Array.from(s.match(/../g).map(b => parseInt(b, 16)));
const toHex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("");

async function buildEnvelope(privateKey /* CryptoKey, Ed25519 */, msg /* 20 | 21 */, e /* GET /api/config .envelope */) {
  const body = new Uint8Array(92);
  const v = new DataView(body.buffer);
  body.set(new TextEncoder().encode("HQMGMT1"), 0);       // byte 7 stays 0
  v.setUint16(8, 1, true);
  v.setUint16(10, msg, true);
  body.set(hex(e.device_id), 12);
  body.set(hex(e.epoch), 28);
  v.setBigUint64(36, BigInt(e.next_seq), true);
  v.setBigUint64(44, 0n, true);
  v.setBigUint64(52, BigInt(e.generation), true);
  body.set(hex(e.digest), 60);
  const tag = new TextEncoder().encode("HQMGMT1-SIG");
  const signed = new Uint8Array(tag.length + body.length);
  signed.set(tag, 0);
  signed.set(body, tag.length);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, signed));
  return toHex(body) + toHex(sig);                        // 312 hex digits
}
```

Reference implementation and test vector: `os/kernel/tools/policy-sign.py mgmt-sign` (and `hq-upload.py
--sign-key ... --config-confirm` / `--config-rollback`). With the private seed `6b` x 32, device id `000102...0f`,
epoch `0102030405060708`, seq 42, msg confirm, generation 9 and digest `5a` x 32, the envelope is:

```
48514d474d54310001001400000102030405060708090a0b0c0d0e0f01020304050607082a0000000000000000000000000000000900000000
0000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5adfc7bdb7a85f4a16d96169c3d59a2637e34e004846b5
5873df5462fe705386a8214d8586401693da20cf3c71ee015f959484845e59d366148730d8ec761d020e
```

(one line, no breaks; the device's `[P-hsh-web]` self-test checks this exact vector).

## Step 3: send it

`POST /api/config/confirm` or `POST /api/config/rollback`, `Content-Type: application/x-www-form-urlencoded`,
headers `Origin` and `X-HQ-CSRF` as for every owner write.

| Field | Required | Notes |
|---|---|---|
| `envelope` | yes | the 312 hex digits |
| `reason` | yes | at least 3 characters (journaled) |
| `permanent` | yes | `true` |
| `seq` | yes | the session write sequence from `/api/session` `next_seq` (unrelated to the envelope's `seq`) |
| `owner_key` | no | ignored; do not send |

Success: `200 {"ok":true,"committed":true,"generation":N}` (confirm) or `{"ok":true,"rolled_back":true,"generation":N}`.

Refusals: `{"ok":false,"refused":"<reason>"}`.

| HTTP | `refused` | What the UI should say / do |
|---|---|---|
| 403 | `origin`, `csrf` | reload the page |
| 409 | `replay` | the session `seq` was reused: re-read `/api/session` |
| 400 | `reason required`, `permanent=true required`, `rate limited: ...` | form problem |
| 403 | `refused: needs an owner-signed envelope` | no or unreadable `envelope` field |
| 403 | `refused: no owner key enrolled` | enroll an owner key first |
| 403 | `refused: malformed envelope` | wrong length / magic / version |
| 403 | `refused: signature is not the owner key's` | wrong key, or the envelope was altered |
| 403 | `refused: envelope is for another device` | wrong `device_id` |
| 403 | `refused: envelope from another boot` | the device restarted: re-read `/api/config` and sign again |
| 403 | `refused: replayed or stale sequence` | re-read `next_seq` and sign again |
| 403 | `refused: envelope is for another operation` | `msg` / `arg` do not match the endpoint |
| 403 | `refused: something else is on trial` | the bundle on trial is not the one signed: show the new generation, ask again |
| 403 | `refused: something else is in force` | rollback signed for a bundle that is no longer in force |
| 403 | `refused: no entropy for the boot epoch` | device fault (no TRNG): report it |
| 400 | `no configuration on trial` | nothing to confirm (the envelope was valid) |
| 400 | `no configuration bundle in force`, `no configuration store on this device`, `refused by cfgd` | as today |
| 400 | `management service unavailable` | device fault |
| 403 | `refused: envelope binds another target` | (activate / upload rollback / rotate) the signed target is not the device's: re-read and sign again |

Every request, accepted or refused, is recorded in the owner journal (type `config`) with its outcome.

## The other envelope endpoints

All take the same `Origin` + `X-HQ-CSRF` headers and the session `seq`; `envelope` is the 312-hex field. Envelope
refusals are HTTP 403 with the `refused: …` reasons in the table above, plus `refused: envelope binds another target`
when the signed type / generation / digest / key is not the one on the device.

**Upload activate.** `POST /api/upload/finish` now also returns `"digest":"<64 hex>"` (the staged content's SHA-256:
the HQCFG1 bundle for `config`, the POLICY.TXT file for `policy`, the pack body for the other packs, the image for
`os_image`), and `GET /api/upload` `in_flight` carries `type_code`, `generation` and `digest` once verified. Before
signing, compare `digest` with the SHA-256 of the owner's own file; if they differ, do not sign. Then
`POST /api/upload/activate` with `id`, `seq`, `envelope` (msg 23, arg = type code, generation + digest as finish
reported). `owner_key` is no longer read. `begin`, `chunk`, `finish` and `abort` are unchanged.

**Upload rollback.** `POST /api/upload/rollback` with `type`, `seq`, `envelope` (msg 24, arg = type code,
generation = the generation to roll back TO, digest zeros). Take that generation from `GET /api/upload`
`types[].rollback_to` (the generation the rollback handler verifies against, from the same function; `null` = nothing
to roll back to, do not offer the button). The device verifies the previous half first; if its generation is not the
signed one: `refused: envelope binds another target`. If there is nothing to roll back to:
`nothing to roll back to (no verified previous generation)` (400).

**Upload history.** `GET /api/upload` `activations[]` lists the owner-journal artifact records (newest first): `seq`,
`ms`, `type` (a pack type, `os_image`, or `config` / `upload` / `owner` / `anchor` / `hsh` for envelope and console
records), `result` and `detail`. `result` is `"ok"` (done: an activation, a rollback, an accepted envelope, a console
command), `"refused"` (refused or failed; nothing changed, or the store went back to the previous pack) or
`"unknown"` (a value this build does not know). Tell an activation from a rollback by `detail`: `gen A->B sha256:…`
(activation), `rollback gen A->B` (rollback), `<op> gen N <reason>` (envelope refusal).

**Factory reset.** `POST /api/factory-reset` with `confirm=ERASE`, `reason`, `permanent=true`, `seq`, `envelope`
(msg 32, arg 0, generation 0, digest zeros). Refusals are 403 as before.

**Owner-key rotation.** `POST /api/anchor/rotate` with `public_key`, `proof`, `generation`, `signature` (HQROT1, as
before), `seq` and `envelope` (msg 33, arg = fingerprint of the CURRENT owner key, generation = the same rotation
`generation`, digest = SHA-256 of the NEW `public_key`). The device checks the envelope with the current key, then
the HQROT1 signature and the proof as before. `owner_key` is no longer read here. First enrollment
(`/api/anchor/enroll`) is unchanged.

Owner-side reference: `policy-sign.py mgmt-sign --msg activate|pack-rollback|factory-reset|rotate …` and
`hq-upload.py --sign-key K_OWN.pem` (activate after an upload, `--rollback TYPE --to-generation N`,
`--factory-reset REASON`, `--rotate ROTATE.TXT`).

## The web console (`POST /api/hsh`)

`POST /api/hsh?seq=N`, owner session, headers `Origin` + `X-HQ-CSRF`, body `text/plain`. `N` (decimal, below 2^32) is the session write
sequence (`/api/session` `next_seq`, one per request, as the `seq` form field of the other writes), and the request
counts against the same 20-writes-a-minute session limit. Refused before the line runs: a missing / reused / stale
`seq` → 409 `{"ok":false,"refused":"replay"}`; over the limit → 400 `{"ok":false,"refused":"rate limited: at most 20
writes a minute per session"}`.

- line 1: the command line (`help`, `info`, `config status`, `owner challenge`, `config confirm`, ...);
- line 2 (optional): the 312-hex envelope for a privileged command (`config confirm`, `config rollback`,
  `config stage <upload-id>`; for stage, `arg` = the upload id and generation / digest = 0).

The answer is `text/plain`. View commands run on the session alone. A privileged command without a valid envelope
answers `ERROR: Configuration rejected. (refused: ...)` with the reasons above. `owner challenge` prints the same
values as `GET /api/config` `envelope`. The journal keeps only the first two command words, never arguments or the
envelope. Session elevation (`owner elevate`) no longer exists.
