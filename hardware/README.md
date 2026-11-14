# hardware/ — HookProbe-designed boards (open hardware)

Board designs made for HookProbe OS. These are hardware *sources* (schematics, layout, generator scripts). How the
OS sees a board is its *profile* in [`appliance/`](../appliance/).

| Design | Status |
|---|---|
| [`hookprobe-sbc/`](hookprobe-sbc/) | RK3588 single-board computer, **rev A: schematic and placement complete, 90/90 checks pass, not routed, never built.** Do not order it from these files. |

**Direction and gates: [ADR 0064](../docs/adr/0064-open-hardware-hookprobe-board.md).** In short: CM5 is the only product
target until it is validated (gate H0). heqk is then ported to a commercial RK3588 board (Radxa ROCK 5B) first,
and only after that to this design.

**Licence.** Not yet chosen. The software is AGPL-3.0 + commercial (`LICENSING.md`). For these design files ADR 0064
D6 recommends CERN-OHL-S-2.0, pending the operator's decision. Until then, no licence is granted for the hardware
files. Third-party datasheets and the Radxa reference schematic are not redistributed here; download them from
their owners.

**Claims.** Until a prototype passes bring-up (ADR 0064 H4), describe this as "an open RK3588 reference design, in
progress", never as a product HookProbe ships.
