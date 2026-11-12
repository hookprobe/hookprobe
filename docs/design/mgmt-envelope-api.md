# Owner-signed management envelopes (HQMGMT1): API for Mission Control

Status: built 2026-11-12 (heqk branch `feat/hsh-prod-transport`), QEMU self-tests `[P-hsh-web]` / `[P-mgmtabi]`,
mc-e2e. Metal: pending. Decision: hsh spec R6 = D (operator, 2026-11-12), hard switch: no compatibility flag.

Audience: the Mission Control UI designer. The device side is done; this page is the contract the UI must follow.

## What changed

`POST /api/config/confirm` and `POST /api/config/rollback` are authorised **only** by an envelope signed with the
owner's configuration key `K_own` (the Ed25519 key enrolled through `/api/anchor/enroll`). The owner session and the
`owner_key` token no longer authorise a change:

- A request without a valid `envelope` is refused (HTTP 403), even with a correct `owner_key`.
- The `owner_key` field is ignored on these two endpoints. Do not send it.
- The device never holds the private key. The browser (or the owner's CLI) signs; the device verifies.

The session, `Origin`, `X-HQ-CSRF`, the per-session `seq` and the write rate limit are unchanged: they gate the
transport only.

The same envelope also authorises the web console (`POST /api/hsh`, see below). Other owner endpoints (reboot,
factory reset, uploads, anchor enroll / rotate, owner rules, actions, alert hook) are **unchanged for now** and still
use `owner_key` re-authentication. They will move to envelopes in a later step; this page will say so when they do.

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
| 10 | 2 | msg | `20` = confirm, `21` = rollback (u16 LE). `22` = stage is used by the shell only. |
| 12 | 16 | device_id | from `envelope.device_id` |
| 28 | 8 | epoch | from `envelope.epoch` |
| 36 | 8 | seq | u64 LE, at least `envelope.next_seq` |
| 44 | 8 | arg | u64 LE, `0` for confirm / rollback |
| 52 | 8 | generation | u64 LE, `envelope.generation` |
| 60 | 32 | digest | `envelope.digest` |
| 92 | 64 | signature | Ed25519 by `K_own` over the ASCII bytes `HQMGMT1-SIG` (11 bytes, no terminator) followed by bytes 0..92 |

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

Every request, accepted or refused, is recorded in the owner journal (type `config`) with its outcome.

## The web console (`POST /api/hsh`)

`POST /api/hsh`, owner session, headers `Origin` + `X-HQ-CSRF`, body `text/plain`:

- line 1: the command line (`help`, `info`, `config status`, `owner challenge`, `config confirm`, ...);
- line 2 (optional): the 312-hex envelope for a privileged command (`config confirm`, `config rollback`,
  `config stage <upload-id>`; for stage, `arg` = the upload id and generation / digest = 0).

The answer is `text/plain`. View commands run on the session alone. A privileged command without a valid envelope
answers `ERROR: Configuration rejected. (refused: ...)` with the reasons above. `owner challenge` prints the same
values as `GET /api/config` `envelope`. The journal keeps only the first two command words, never arguments or the
envelope. Session elevation (`owner elevate`) no longer exists.
