# 2026-11-08 unattended metal round (relay rig) — image 5545d122 + H10 mgmt-subnet guard

```
== cm5-metal-loop 2026-11-08T17:52:32+02:00 image=hookprobe-heqk-cm5-5545d122-zerolinux.img sha256=1519b0c5650471a1
-- 1/4 relay: rpiboot
CM5 boot ROM enumerated — run rpiboot -d mass-storage-gadget64 next
-- 2/4 flash + verify
   (--confirm-erase given)
== 4/4 verify: reading back 536870912 bytes...
VERIFIED: eMMC content == image (sha256 1519b0c5650471a118be61033a4e0687871172e5be6310e0103a354e4b0d090b)
NEXT: remove the nRPIBOOT jumper, start the serial capture, then power-cycle the CM5.
-- 3/4 relay: boot (serial mark 1137283)
power-cycled for a normal eMMC boot
-- 4/4 waiting up to 300s for 7 markers
ok   secure boot: PASS (ed25519 AND SLH-DSA, svn OK)
ok  C [HBoot-AB] PASS — trial boot confirmed; EL2 watchdog disarmed, slot committed [BOOT-TIMING] t=+10026 ms (watchdog budget 15 s)
ok   [P10-B] PASS — firmware (609309 B) + NVRAM uploaded; F2 ready (firmware alive) (stage-B step 8)
ok   [WIFI] per-device MAC 76:0d:02:f8:d2:da (locally administered, derived from the device secret)
ok   [P11-AP2] PASS(ap-config-wpa2) — WPA2 BSS up (try 1); join "HookProbe-Setup-R3Q1" (PSK from the per-device setup credential); client isolation (ap_isolate) O
ok   [M-NAT0] PASS — end0 WAN uplink leased + gateway resolved + INTERNET reachable (8.8.8.8 ttl=118)
ok   [AP-MC] Mission Control also on https://192.168.200.146/ (management VLAN; the signed `mgmt in` policy applies)
RESULT: PASS (58s after power-on)

login: ok
H-ok   hold TEST-NET 203.0.113.9 120 s: {"ok":true,"id":1} [200]
H7     replay same seq:                 {"ok":false,"refused":"replay"} [409]
H8a    foreign Origin:                  {"ok":false,"refused":"origin"} [403]
H9     ttl=999999:                      {"ok":false,"refused":"ttl out of bounds"} [400]
H10    hold mgmt 192.168.200.1:         {"ok":false,"refused":"management floor"} [400]
H5neg  shield_allow wrong owner key:    {"ok":false,"refused":"re-authentication failed"} [403]
revoke 1: {"ok":true,"id":0} [200]
active after revoke: 0
```
