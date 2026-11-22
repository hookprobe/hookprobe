# s1-pop — S1: a heqk `qemu-itest` guest on fortress against the real G19 super-PoP

Operator decisions, 2026-11-22:
- (1) entropy: virtio-rng only in a dedicated QEMU integration-test profile;
- (2) S1 runs as an isolated QEMU guest on fortress, over a dedicated restricted interface, to the S0 test PoP on
  the A1 (`onboarding/enrollment/superpop/deploy/S0-RUNBOOK.md`);
- per-VM VEK;
- separate evidence classes;
- no production or release-gate changes.

## Evidence classes (never mixed)

| Class | What | Produced by |
|---|---|---|
| E1 QEMU local | `validate.sh` / `mc-e2e.sh` rows (`[P-g19]`, `qemu-itest` entropy/VEK tests); simulated PoP | heqk session |
| **E2 QEMU → real PoP** | this harness: the guest ↔ the real `superpop` on 130.61.174.233 over the internet | `s1-vm.sh evidence` |
| E3 CM5 metal | the bench CM5 against the same PoP | heqk session, metal batch |

An E2 record is labelled "NOT metal" and never marks a metal gate.

## Isolation (what the guest can and cannot do)

| Control | Where |
|---|---|
| Dedicated interface: netns `hqs1`, veth `hqs1-h`/`hqs1-g` (10.254.19.0/30), IPv6 off | `s1-net.sh up` |
| Outbound allowlist: **only** 130.61.174.233 UDP 7654/7655; PoP replies only on established flows; nothing reaches fortress | nft `inet hqs1` (host firewall) |
| Second allowlist on the QEMU process itself | systemd `IPAddressDeny=any IPAddressAllow=<PoP>` |
| Leaves `ppp0` / PPPoE alone: NAT through the default route in a separate table; no route or `ip_forward` change | `ip hqs1_nat` |
| CPU 100% of one core, 2 GiB RAM, no swap, 64 tasks, max file size 256 MiB, 2 h wall clock, 64 MiB fixed-size disk | `s1-vm.sh run` (systemd-run) |
| No host-filesystem sharing: no virtfs, **no `-semihosting`** (it gives the guest host file I/O); the sandbox sees only its own VM dir | `ProtectSystem=strict`, `ProtectHome`, `ReadWritePaths` |
| No device passthrough: `PrivateDevices`, `DevicePolicy=closed`, no `/dev/kvm` (TCG) | systemd-run |
| No privileges: dedicated user `hqs1`, empty capability set, `NoNewPrivileges` | systemd-run |
| Data volume: host-partitioned (one 0xDA DataVolume from LBA 2048; heqk never writes LBA 0). Per-VM KEK: 32 B in `keys/`, outside `disk/`; reaches the guest only via read-only fw_cfg `opt/hookprobe/kek`; shredded on destroy; no reuse, no sharing | `s1-vm.sh new/destroy` |

## Run (needs sudo; operator)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hqs1        # once
sudo tools/s1-pop/s1-net.sh up && sudo tools/s1-pop/s1-net.sh verify         # must print PASS
# kernel: built by the heqk session — feature `qemu-itest` (+ mcserve,wpa3,hsh,securechannel), with
#   HEQK_POP_PUB=<the S0 test PoP's 1216-byte blob> and a signed POLICY line `tunnel pop 130.61.174.233 full`
sudo tools/s1-pop/s1-vm.sh new s1a
sudo tools/s1-pop/s1-vm.sh run s1a <kernel.bin>
grep -a '\[ITEST\] device identity' /var/lib/hookprobe-s1/vms/s1a/run/serial.log   # → add the pk to the S0 allowlist
sudo tools/s1-pop/s1-vm.sh evidence s1a
sudo tools/s1-pop/s1-vm.sh new s1b && sudo tools/s1-pop/s1-vm.sh wrongkey s1a s1b <kernel.bin>   # must refuse
sudo tools/s1-pop/s1-vm.sh rotate s1a <kernel.bin>      # one boot offering opt/hookprobe/kek-next; guest re-wraps the VEK
sudo tools/s1-pop/s1-vm.sh stop s1a && sudo tools/s1-pop/s1-vm.sh rotate-commit s1a   # kek-next → kek, old KEK shredded
sudo tools/s1-pop/s1-vm.sh destroy s1a; sudo tools/s1-pop/s1-net.sh down
```

## Tests

- `tests/netns-e2e.sh` (unprivileged, `unshare -Urnm`) runs `s1-net.sh up/verify/down` for real against a simulated
  fortress + internet. It covers:
  - only UDP 7654/7655 to the PoP leaves, masqueraded;
  - PoP replies return, unsolicited packets don't;
  - TCP, ICMP, other ports and fortress services are all blocked;
  - teardown is complete.

  14/14 pass. A ruleset with its drops removed fails 5 checks.
- `s1-vm.sh`: the QEMU device line was accepted by QEMU 8.2.2, and the sandbox properties pass `systemd-analyze verify`.
  The real guest run waits on the heqk `qemu-itest` image.
