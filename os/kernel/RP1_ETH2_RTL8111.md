# 2nd Ethernet (eth1) — Realtek RTL8111H — future target

The Waveshare CM5-DUAL-ETH-MINI's second port (the RJ45 **nearest the USB-C**;
`end0`/GEM is the one furthest from USB-C).

## Identity
- **RTL8111H** — PCIe Gigabit MAC+PHY, Linux `r8169`, PCI ID `10ec:8168`.
- PCIe endpoint on **BCM2712 external RC1 = `pcie@1000110000`** (domain 0001),
  BDF `0001:01:00.0`, Linux name `enP1p1s0`. (RP1 GEM is domain 0000 on RC2
  `pcie@1000120000` — a different root complex.)

## Why it's harder than the GEM (the gating blocker)
The RP1 GEM was reachable because firmware always trains RC2 (RP1 provides
essential I/O). **RC1 (external) is NOT trained/enumerated by firmware by
default.** To reach the RTL8111H bare-metal we must first implement:
1. BCM2712 brcmstb PCIe RC1 host-bridge init @ `0x10_0011_0000`: deassert PERST,
   program inbound/outbound windows + DMA ranges, TRAIN the link (poll L0).
2. ECAM config-space access to `0001:01:00.0`, confirm `10ec:8168`.
3. Assign/enable the endpoint BAR + outbound window; set Bus-Master + Mem-Space.
Then the MAC bring-up (below) is easy. The PCIe RC layer is the real cost.

## RTL8111H MAC bring-up (once BARs reachable — POLLED RX)
MMIO offsets (r8169): MAC0=0x00, ChipCmd(CR)=0x37 (Reset=0x10, RxEnb=0x08,
TxEnb=0x04), IMR=0x3C, ISR=0x3E, RxConfig=0x44 (AcceptBroadcast=0x08,
AcceptMyPhys=0x02, AcceptAllPhys=0x01), Cfg9346=0x50 (unlock=0xC0/lock=0x00),
PHYstatus=0x6C (link/speed — PHY self-configures, no MDIO needed), RxMaxSize=0xDA,
CPlusCmd=0xE0, RxDescAddrLow/High=0xE4/0xE8, TxDescStart=0x20/0x24.
RX descriptor (16 B, ring 256-B aligned): opts1 = OWN(1<<31, NIC clears on RX) |
EOR(1<<30 last) | len(low14); opts2; addr(u64). Poll OWN clear -> len=opts1&0x3fff.
Seq: reset -> unlock Cfg9346 -> read MAC -> RX ring (OWN|bufsize, EOR on last) ->
RxDescAddr -> RxMaxSize -> RxConfig accept bits -> CR RxEnb|TxEnb -> lock -> IMR=0
-> poll. Self-configuring PHY, no firmware blob.

## References
OSDev RTL8169, SerenityOS Kernel/Net/RTL8168NetworkAdapter, Linux r8169_main.c,
brcm-pcie (brcmstb) + bcm2712.dtsi PCIe nodes for the RC1 bring-up.

## Verdict
Good 2nd target on MAC merits, but only AFTER a BCM2712 external-PCIe-RC bring-up
layer exists. Not "soon" unless PCIe RC work is scheduled. The GEM (end0) stays
the current focus — no PCIe work needed.
