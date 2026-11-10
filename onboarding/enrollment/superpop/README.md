# superpop — the G19 super-PoP (SASE tunnel endpoint)

An operator-run service: heqk devices that are configured with a PoP carry their tunnelled LAN
traffic to it over the **same PQ-hybrid Noise IK channel** they use for enrollment, and the PoP
forwards it to the internet. It runs on a Linux server (ADR 0044 D3: heavy services may be hosted
off-device). The device never depends on it: **no PoP configured ⇒ no tunnel** (standalone by default).

Like `responder-sim`, it compiles the kernel's own `os/kernel/kernel/src/securechannel.rs` (`#[path]`),
so its handshake and record bytes are the device's by construction.

## Wire format — G19 v1 (the device mirrors this)

| | |
|---|---|
| Handshake | the existing chunked msg1/msg2 framing, **unicast** UDP to `<pop>:7654`; msg1 payload = `sha256(device pk)`; msg2 payload = tenant LE64. msg2 goes back to the msg1 source address/port. |
| Data | UDP `7655`, datagram = `"HQT1"(4) ‖ sid(8) ‖ LE64 seq ‖ ciphertext ‖ tag16` (`Session::seal_record` / `AntiReplayRx::open_record`, RFC 6479 window) |
| AD | `"HQT1" ‖ sid` |
| sid | `SHA-256("HQ-G19-sid-v1" ‖ Session.handshake_hash)[0..8]`, fresh per session, unlinkable |
| Endpoint | learned from, and re-bound on, every **authenticated** data record (roaming / NAT rebinding); a forged record never moves it |

Record plaintext = `type(1) ‖ body`:

| type | name | direction | body |
|---|---|---|---|
| `0x01` | DATA | both | one IPv4 packet (IPv6 reserved; dropped in v1) |
| `0x02` | KEEPALIVE | both | empty. The device sends it when idle 15 s; **the PoP echoes it**, so a device that hears nothing for ~45 s re-handshakes (e.g. after a PoP restart). |
| `0x03` | ASSIGN | PoP→dev | `inner_v4(4) ‖ plen(1) ‖ dns_v4(4) ‖ mtu LE16` |
| `0x04` | ADDR_REQ | dev→PoP | empty. Send right after the handshake (it also teaches the PoP the data endpoint). |
| `0x05` | CLOSE | both | `reason(1)`: 1 shutdown, 3 rekey (2 is reserved) |

PoP policy, enforced here:
- **Anti-spoofing:** DATA must have src = the device's assigned inner address.
- **No device-to-device routing:** dst inside the pool is dropped.
- **One live session per device:** a re-handshake replaces and wipes the old session.
- **Expiry:** idle sessions are dropped after 120 s, and any session after 25 h; devices re-handshake every 24 h.
- **Handshake rate limit:** 6 completed msg1 per source IP per minute, with at most 256 concurrent reassemblies.
- **Unauthorised devices:** a device that isn't allowlisted completes no handshake, so it gets **silence**. There are no keys to send it an authenticated CLOSE with.

Device-side duties (heqk): send the handshake unicast to the PoP from a signed config entry, and ADDR_REQ after Established. NAT the tunnelled LAN flows to the assigned inner /32. Clamp TCP MSS to `mtu-40`. Send KEEPALIVE when idle 15 s. Re-handshake on 45 s of silence and at 24 h. Tunnel policy (full or split) comes from the signed policy family.

## Run it

```bash
cargo build --release                                  # onboarding/enrollment/superpop
./target/release/superpop keygen --key-file /etc/superpop/pop.key      # 0600; prints the public blob
#   bake the 1216-byte public blob into device images as the pinned PoP key (same format as
#   os/kernel/kernel/src/testdata/provisioned_mssp_pub.bin)
cat > /etc/superpop/devices <<'EOF'
# name      ed25519 pk (the device prints `[NETCP] device identity (SRK-derived) pk=…`)   inner
cm5-bench   <64 hex chars>                                                                100.64.0.2
EOF
sudo ./target/release/superpop run --key-file /etc/superpop/pop.key --devices /etc/superpop/devices --tenant 54454e41
sudo ./superpop-net.sh hqpop0 <wan-if>                 # address, forwarding, nft forward policy + NAT + MSS clamp
```

`run` needs `CAP_NET_ADMIN` only to create the TUN. A systemd unit can grant it with `AmbientCapabilities=CAP_NET_ADMIN` and a dedicated user.

## Tests

- `cargo test`: the wire codec, plus an in-process **end-to-end scenario** in which a device built from the kernel's real initiator code covers:
  - handshake, ASSIGN, and DATA in both directions;
  - anti-spoofing, device-to-device blocking, and replay rejection;
  - NAT rebinding, and a forged record that must not rebind;
  - a rogue device, a fingerprint mismatch, re-handshake replacement, and idle expiry;
  - the per-source rate limit, and allowlist validation.

  CI runs it in gate g1.
- `superpop selftest`: the same scenario on an operator host.
- `tests/netns-e2e.sh`: the **real I/O path**, unprivileged (`unshare -Urn`). It runs a real UDP handshake through a real TUN, and an ICMP echo answered by the kernel comes back sealed through the tunnel; a rogue device is refused. It's local-only, because GitHub's Ubuntu 24.04 runners restrict unprivileged user namespaces.

## Follow-ups

1. **Kernel API: set-based msg1 authentication.** `responder_read_msg1` checks one enrolled key, so the PoP tries the allowlist in turn: one ML-KEM decapsulation per device, bounded by the rate limit. A variant taking a lookup over the decrypted identity removes the O(n). Requested from the kernel side.
2. **Kernel API: a host responder constructor** without the `securechannel-selftest` accessors. `ResponderStatic::from_seeds` is selftest-gated today, so this crate enables that feature, the same as `responder-sim`.
3. IPv6 inner traffic (DATA with version 6) is reserved in v1.
