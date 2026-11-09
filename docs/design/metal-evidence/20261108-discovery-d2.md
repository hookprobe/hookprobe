# 2026-11-08 discovery D2 — passive mDNS/SSDP, image 91a4d77e + D2, real client (Pi 4, avahi)

```
   10.99.0.10 hookprobe-test | mdns: hookprobe-test [a8:29:48:33:73:5 None svc 512 |  None computer  high
D2-DISCOVERY: PASS
```

LAN-client regression on this image: 9/10 in the round (IPv6 checked before SLAAC settled), 10/10 once settled; the suite now waits for the IPv6 default route.
