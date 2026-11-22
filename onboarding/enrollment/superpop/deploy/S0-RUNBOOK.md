# S0 — G19 super-PoP test tenant on a shared Linux host (operator runbook)

**Status:** applied to the operator's test PoP on 2026-11-22. Host-specific values (addresses, interfaces, paths)
live only in the operator's deployment, never in this repository.

Scope (operator, 2026-11-22):
- a single-tenant **test** PoP for our own devices, sharing a host with other services;
- tunnel egress shares the host's public address;
- multi-tenant stays refused (ADR 0062);
- S1 runs are class **E2: QEMU-to-real-PoP** evidence, never metal.

## Before you start

| Check | Why |
|---|---|
| **Find the host's own public IPv4.** Devices must use that address, not a website hostname behind a proxy or CDN. | Proxies and CDNs do not carry this UDP, and the POLICY `tunnel pop <ipv4>` line is IPv4-literal anyway. |
| **Check whether the host firewall is a drop-policy table** (e.g. `inet hookprobe_vrf`). | If so, `superpop-net.sh` alone is not enough: the PoP would receive nothing. Add the `setup-vrf-g19.nft` lines to the table's **generator**, because a regeneration or a self-heal restart reverts hand edits. |
| **Check UDP 7654/7655 are free** (`ss -lun`). | They are the handshake and data ports. |
| **Check that the cloud provider's ingress rules can be changed.** | UDP 7654–7655 must be allowed in from the internet. |

## Steps

1. **Build.** For an arm64 host, cross-build from an x86 machine and self-test the artifact:
   ```bash
   cd onboarding/enrollment/superpop
   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
     cargo build --release --locked --target aarch64-unknown-linux-gnu
   qemu-aarch64-static -L /usr/aarch64-linux-gnu target/aarch64-unknown-linux-gnu/release/superpop selftest   # PASS
   ```
2. **Firewall.**
   - Back up the live ruleset: `sudo nft list ruleset > nft-before-g19.nft`.
   - Insert the `setup-vrf-g19.nft` rules into the live table atomically, with no reload. Use `nft add rule … position <handle>`; get the handles from `nft -a list chain …`.
   - Persist the same lines in the table's generator, so a regeneration keeps them.
   - `deploy/tests/vrf-g19-e2e.sh` proves the rules without privileges: 11/11 pass, and a weakened ruleset fails.
3. **Ingress.** Allow UDP 7654–7655 from 0.0.0.0/0 in the cloud provider's security rules. This is the operator's step.
4. **Install:**
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin superpop
   sudo install -m 0755 superpop /usr/local/bin/superpop
   sudo install -m 0755 superpop-net.sh /usr/local/sbin/superpop-net.sh
   sudo install -d -m 0750 -o superpop -g superpop /etc/superpop
   sudo install -m 0640 -o superpop -g superpop deploy/superpop.env.example /etc/superpop/superpop.env   # then edit
   sudo -u superpop /usr/local/bin/superpop keygen --key-file /etc/superpop/pop.key    # 0600
   sudo -u superpop /usr/local/bin/superpop pub --key-file /etc/superpop/pop.key        # → HEQK_POP_PUB (hex)
   ```
   This is a **test** key, used for this tenant only. Custody of the production PoP key is still open (ADR 0050
   step 4). Without a TPM, the key sits on disk.
5. **Allowlist.** Put only test identities in `/etc/superpop/devices`, one per line:
   `name  <ed25519 pk hex>  198.18.0.N`.
   - `superpop devsim --seed <tag> --print-pk` gives a simulator identity.
   - A heqk `qemu-itest` guest prints `[ITEST] device identity pk=…`.
   - Never list a customer device.
6. **Service:**
   ```bash
   sudo install -m 0644 deploy/superpop.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now superpop
   ```
   Then check that:
   - `ip -br addr show hqpop0` shows the pool gateway;
   - `journalctl -u superpop` shows "N device(s) allowed";
   - `nft list table ip superpop_nat` shows the masquerade rule.
7. **End-to-end check** from any internet host:
   `superpop devsim --seed <tag> --pop <POP_IP> --pop-pub <hex> --ping 1.1.1.1` must print
   ESTABLISHED, then ASSIGN, then PASS. Then confirm the tunnel cannot reach the metadata service or private
   ranges: the same command with `--ping 169.254.169.254` must get no reply.
8. **Rollback** (fully reversible):
   - `sudo systemctl disable --now superpop` (its stop step removes its nft tables);
   - delete the inserted rules, or restore the backup;
   - revert the generator change;
   - remove the ingress rule.

## Test tenant

| Setting | Value |
|---|---|
| Tenant id | `0x53315f54455354` ("S1_TEST") |
| Inner pool | `198.18.0.0/15` (RFC 2544) |
| MTU | 1380 |
| DNS | 1.1.1.1 |

Tunnelled devices reach the public internet only. They cannot reach private or cloud-internal ranges, the
metadata service, container networks, CGNAT, multicast, each other, or any service on the PoP host.
