# 2026-11-08 G17 stage 1 — IPv6 on an Ethernet (DHCP) WAN, unattended relay round (image b6ebdcba + G17)

Bench: fortress port 4 VLAN 100, radvd (M=1) + kea DHCPv6-PD /60 from 2001:db8:ff00::/48 (`fortress-vlan-bench.sh v6up`).

```
== cm5-metal-loop 2026-11-08T18:17:24+02:00 image=hookprobe-heqk-cm5-b6ebdcba-zerolinux.img sha256=f37a8a1c3bb2d2c4
-- 1/4 relay: rpiboot
CM5 boot ROM enumerated — run rpiboot -d mass-storage-gadget64 next
-- 2/4 flash + verify
   (--confirm-erase given)
== 4/4 verify: reading back 536870912 bytes...
VERIFIED: eMMC content == image (sha256 f37a8a1c3bb2d2c47647c9116da0d4eabce516fb8ec08f1bc7299ad9ab025b54)
NEXT: remove the nRPIBOOT jumper, start the serial capture, then power-cycle the CM5.
-- 3/4 relay: boot (serial mark 2189712)
power-cycled for a normal eMMC boot
-- 4/4 waiting up to 300s for 7 markers
ok   secure boot: PASS (ed25519 AND SLH-DSA, svn OK)
ok  C [HBoot-AB] PASS — trial boot confirmed; EL2 watchdog disarmed, slot committed [BOOT-TIMING] t=+10024 ms (watchdog budget 15 s)
ok   [P10-B] PASS — firmware (609309 B) + NVRAM uploaded; F2 ready (firmware alive) (stage-B step 8)
ok   [WIFI] per-device MAC 76:0d:02:f8:d2:da (locally administered, derived from the device secret)
ok   [P11-AP2] PASS(ap-config-wpa2) — WPA2 BSS up (try 1); join "HookProbe-Setup-R3Q1" (PSK from the per-device setup credential); client isolation (ap_isolate) O
ok   [M-NAT0] PASS — end0 WAN uplink leased + gateway resolved + INTERNET reachable (8.8.8.8 ttl=118)
ok   [AP-MC] Mission Control also on https://192.168.200.146/ (management VLAN; the signed `mgmt in` policy applies)
RESULT: PASS (59s after power-on)

ok  device: IPv6 router seen on the Ethernet WAN
ok  device: delegated prefix received
ok  device: LAN numbered from the delegated prefix (RA on the AP)
   |  [WAN6] Ethernet WAN: link-local fe80::[00, 00, 00, ff, fe, 00, 00, 02] | router seen [00, d0, b4, 03, b7, 11] | RS tx=1 DHCPv6 tx=2 rx=2 reply=true
   |  [WAN6] DELEGATED PREFIX [2001, db8, ff00, 0, 0, 0, 0, 0]/60 valid=3600s (the LAN would be numbered from this)
   |  [V6LAN] LAN numbered from [20, 1, d, b8, ff, 0, 0, 0]/60: router 2001:db8:ff00:0::1/64 — RA (SLAAC, MTU 1492, RDNSS=false) on the AP, stateful firewall default-deny in
ok  router: kea delegated 2001:db8:ff00::/60
ok  router: ping6 fe80::0000:00ff:fe00:0002%enp4s0.100 (the CM5 answers ND + echo on its WAN link-local)
WAN6-CHECK: PASS
```
