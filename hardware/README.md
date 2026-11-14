# hardware/ — HookProbe board designs (open hardware, work in progress)

Board designs made for HookProbe OS, published while they are being built so the work can be seen and
reviewed. How the OS sees each board is its *profile* in [`appliance/`](../appliance/).

| Design | Status |
|---|---|
| [`hookprobe-sbc/`](hookprobe-sbc/) | RK3588 board, **rev A: schematic and placement complete, 90/90 design checks pass. Not routed, never built. Do not manufacture or order from these files.** |

Direction, gates and status: [ADR 0064](../docs/adr/0064-hookprobe-hardware-program.md) and the
[hardware roadmap in the README](../README.md#hardware-roadmap-the-hookprobe-board).

## Review and feedback

Rev A is published so people can check it while it is still cheap to change. The most useful feedback right now:
- the RK3588 / LPDDR4X circuits and the power tree (`docs/hookprobe-sbc-schematic.pdf`, `design/power_check.py`);
- PCIe lane allocation and the M.2 slots, especially the Wi-Fi 7 slot's power and link (see the
  [ADR 0064 consequences](../docs/adr/0064-hookprobe-hardware-program.md#consequences));
- parts still to confirm (listed under "What is not done" in [`hookprobe-sbc/README.md`](hookprobe-sbc/README.md)).

Open an [issue](https://github.com/hookprobe/hookprobe/issues) or a
[Discussion](https://github.com/hookprobe/hookprobe/discussions), naming the sheet and the reference
designator. Pull requests change the generator scripts (`schematic/build.py`, `schematic/build_pcb.py`), never
the generated `.kicad_*` files, and include a regenerated `VALIDATION.md`.

## Licence

Dual-licensed (ADR 0064 D6):
- **CERN-OHL-S-2.0** ([`LICENSE-CERN-OHL-S-2.0.txt`](LICENSE-CERN-OHL-S-2.0.txt)), or
- **a commercial hardware licence** from HookProbe, for closed derivatives or white-label units.
  Contact qsecbit@hookprobe.com.

The **"HookProbe" name and any "HookProbe Certified" mark are not licensed** by either. A board you build
from these files is not a HookProbe product unless HookProbe certifies it.

Licence notice, for every design in this directory:

> Copyright HookProbe 2026.
>
> This source describes Open Hardware and is licensed under the CERN-OHL-S v2.
>
> You may redistribute and modify this source and make products using it under the terms of the CERN-OHL-S v2
> (https://ohwr.org/cern_ohl_s_v2.txt).
>
> This source is distributed WITHOUT ANY EXPRESS OR IMPLIED WARRANTY, INCLUDING OF MERCHANTABILITY,
> SATISFACTORY QUALITY AND FITNESS FOR A PARTICULAR PURPOSE. Please see the CERN-OHL-S v2 for applicable
> conditions.
>
> Source location: https://github.com/hookprobe/hookprobe/tree/main/hardware
>
> As per CERN-OHL-S v2 section 4, should You produce hardware based on this source, You must where practicable
> maintain the Source Location visible on the external case of the product or other products you make using
> this source.

## Third-party material

Not covered by the licence above, and remaining subject to its owners' terms:
- component symbols and footprints under `hookprobe-sbc/vendor/` (from the LCSC/EasyEDA library);
- circuit values that follow the published Radxa ROCK 5B v1.45 reference schematic. The Radxa schematic itself
  and all component datasheets are **not** in this repository; download them from their owners.
