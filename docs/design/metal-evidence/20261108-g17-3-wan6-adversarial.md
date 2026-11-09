# 2026-11-08 G17.3 — IPv6 firewall parity, attacked from the WAN (port-4 bench, live board, image b6ebdcba + G17)

```
   route 2001:db8:ff00::/60 via fe80::ff:fe00:2
   before: drop no_flow=0
ok  unsolicited ping6 to 2001:db8:ff00::99 gets no answer
ok  unsolicited TCP SYN to 2001:db8:ff00::99 :22/:80/:443/:3389 — no connection
ok  the device counted the unsolicited inbound (drop no_flow 0 -> 15)
ok  the CM5 WAN link-local fe80::ff:fe00:2 still answers
   after:  drop no_flow=15 no_neigh=0 hop=1 src=0
WAN6-ADVERSARIAL: PASS
```
