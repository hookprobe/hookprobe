# Blocking AP clients from upstream private networks (LAN assessment A-01)

**Status:** an owner option. No default change and no new code.

## The finding

Wi-Fi clients of the HookProbe AP can reach private networks on the WAN side of the device. In the bench
assessment (2026-11-14), a client reached:
- 192.168.200.1:22, the router's host on the management VLAN;
- 10.200.0.1, the upstream LAN router.

The device NATs client traffic out of the WAN, and whatever is upstream answers.

## Why it is not blocked by default

- ADR 0023 / the enforcement-separation rule: legitimate traffic always passes unless the owner says
  otherwise.
- In many homes, the upstream private network is where the ISP router's admin page, a NAS or a printer lives.
  Owners reach those from Wi-Fi on purpose.
- A default block would break them silently.

## How an owner blocks it

Add these lines to the signed `POLICY.TXT` (or the policy section of an HQCFG1 bundle):

```
prefix-list UPSTREAM-PRIVATE seq 5 deny 10.99.0.0/24 le 32
prefix-list UPSTREAM-PRIVATE seq 10 permit 10.0.0.0/8 le 32
prefix-list UPSTREAM-PRIVATE seq 20 permit 172.16.0.0/12 le 32
prefix-list UPSTREAM-PRIVATE seq 30 permit 192.168.0.0/16 le 32
acl LAN-IN seq 10 block any any pl:UPSTREAM-PRIVATE
acl LAN-IN default allow
interface lan acl in LAN-IN
```

- Seq 5 carves out the AP's own client subnet. `deny` means "not in this list", so DNS, DHCP and the
  gateway on 10.99.0.1 keep working. Change it if the AP subnet differs.
- `block` refuses the connection at once (TCP RST or ICMP admin-prohibited) instead of a silent drop, so a
  client sees "refused" rather than a hang.
- To allow one upstream device (for example the ISP router at 192.168.1.1), add a `deny` line for it with a
  lower seq than the permits, e.g. `prefix-list UPSTREAM-PRIVATE seq 6 deny 192.168.1.1/32`.
- `LAN-IN` must be the only ACL bound to `lan in`. Merge these entries into an existing one if the policy
  already binds one.

## Proof

`hal::policy::a01_upstream_private_tests` (host unit tests, now run in CI g1) parse exactly this snippet and
check:
- client → 192.168.200.1:22, 10.200.0.1:443, 172.20.200.5:80 and 192.168.1.1:80 are **blocked**;
- client → 10.99.0.1:53, 1.1.1.1:443 and 93.184.216.34:80 are **allowed**;
- without the lines, nothing is blocked.

Shown on metal 2026-11-14 (`docs/design/metal-evidence/20261114-late.md` §3): applied as a signed live bundle, a Wi-Fi client was refused at once on 192.168.200.1:22 and 172.20.200.1:22, DNS and the internet kept working, and restoring the previous policy made them reachable again.
