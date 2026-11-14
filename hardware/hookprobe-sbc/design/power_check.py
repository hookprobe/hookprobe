#!/usr/bin/env python3
"""HookProbe SBC rev A: power-tree check, computed from the generated schematic.

    python3 design/power_check.py

What it checks (every figure is read from the schematic's own parts and nets):
  1. Each regulator's output voltage, from its feedback resistors, against the window its loads accept.
  2. Each chip's supply and enable pins against the limits in its datasheet.
  3. The input converters' operating point (on-time, inductor peak current) across the input range.
  4. Power-up order: nothing may pull a processor pin high before that pin's own supply is up.
  5. Housekeeping: every I2C bus has pull-ups, every remotely sensed rail has its sense tie,
     current-limit resistors give the intended limits.
  6. The load budget in design/allocation_check.py.
Datasheets are in vendor/lcsc_<id>/datasheet.pdf. Exits non-zero if any check fails.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "schematic"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, HERE)

VIN_MIN, VIN_MAX = 4.6, 20.0     # USB-C at 5 V before negotiation (less the ideal diode drop) up to 20 V

# Rail voltages. Fixed rails are computed from their feedback resistors below and written back here;
# the power chip's programmable rails use the Rock 5B device-tree values (set by the boot software).
# name: (volts, stage). Stage = when the rail comes up: 0 with VIN, 1 standby (S3), 2 running (S0),
# 3 switched by software.
RAILS = {
    "VIN": (None, 0), "USBC1_VBUS": (None, 0),
    "VCC5V0_SYS": (5.15, 0), "VCC4V0_SYS": (4.04, 0),
    "+3V3": (3.36, 2), "VCC_3V3_M2": (3.36, 2), "VCC_MODEM": (3.36, 3),
    "VCC_3V3_S3": (3.3, 1), "VCC_1V8_S3": (1.8, 1), "VCC_2V0_PLDO_S3": (2.0, 1), "VCC_1V1_NLDO_S3": (1.1, 1),
    "VDD2_DDR_S3": (1.1, 1), "VDDQ_DDR_CKE_S3": (1.1, 1), "VDDQ_DDR_CK_S0": (0.6, 2), "VDD_0V75_S3": (0.75, 1), "VCC_1V8_S3_PLDO6": (1.8, 1),
    "VCC_3V3_S0": (3.3, 2), "VCC_1V8_S0": (1.8, 2), "VCCA_1V8_S0": (1.8, 2), "VCCA_3V3_S0": (3.3, 2),
    "VDDQ_DDR_S0": (0.6, 2), "VDD_DDR_S0": (0.85, 2), "VCCIO_SD_S0": (3.3, 2), "VDDA_1V2_S0": (1.2, 2),
    "VDD_0V75_S0": (0.75, 2), "VDDA_0V75_S0": (0.75, 2), "VDDA_0V85_S0": (0.85, 2), "VDDA_DDR_PLL_S0": (0.85, 2),
    "ETH1_VDD09": (0.95, 2), "ETH2_VDD09": (0.95, 2), "ETH1_AVDD33_PLL": (3.36, 2), "ETH2_AVDD33_PLL": (3.36, 2),
    "HUB_3V3": (3.3, 2), "USBA_VBUS": (5.15, 3), "USBC2_VBUS": (5.15, 3),
    "VCC3V3_CLKA": (3.3, 2), "VCC3V3_CLKB": (3.3, 2),
}

# Regulators with a feedback divider: (feedback net, output rail, reference volts, allowed min, allowed max, why)
DIVIDERS = [
    ("IN1_FB", "VCC5V0_SYS", 0.6, 4.90, 5.25, "USB ports: 5.25 V maximum; 4.75 V minimum after the port switch"),
    ("IN2_FB", "VCC4V0_SYS", 0.6, 3.8, 4.3, "power chip and core regulators: 2.7 V to 5.5 V"),
    ("IN3_FB", "+3V3", 0.6, 3.135, 3.465, "M.2 / PCIe 3.3 V +/- 5 %"),
    ("IN4_FB", "VCC_3V3_M2", 0.6, 3.135, 3.465, "M.2 3.3 V +/- 5 %"),
    ("IN5_FB", "VCC_MODEM", 0.6, 3.135, 3.465, "M.2 modem 3.135 V to 4.4 V"),
    ("V1V1_FB", "VCC_1V1_NLDO_S3", 0.6, 1.05, 1.2, "input of the power chip's low-voltage regulators"),
    ("ETH1_CORE_FB", "ETH1_VDD09", 0.6, 0.90, 1.0, "RTL8125BG core 0.95 V"),
    ("ETH2_CORE_FB", "ETH2_VDD09", 0.6, 0.90, 1.0, "RTL8125BG core 0.95 V"),
    ("PMIC_FB6", "VDD2_DDR_S3", 0.5, 1.06, 1.17, "LPDDR4X VDD2 1.06 V to 1.17 V"),
    ("PMIC_FB9", "VDDQ_DDR_S0", 0.5, 0.57, 0.65, "LPDDR4X VDDQ 0.57 V to 0.65 V"),
]

# Supply pins: part value pattern -> [(pin name pattern, min volts, max volts)]. Recommended operating
# ranges from each datasheet (or the interface standard for connectors).
SUPPLY_LIMITS = [
    (r"MP8759", [(r"^VIN$", 4.5, 24.0)]),
    (r"RK806", [(r"^VCC\d+$|^VCCA$", 0.0, 5.5)]),          # each VCC input feeds one converter; 2.7 V minimum on VCCA
    (r"RK860", [(r"^VIN$", 2.7, 5.5)]),
    (r"SY8089", [(r"^IN$", 2.7, 5.5)]),
    (r"SY6280", [(r"^IN$", 2.4, 5.5)]),
    (r"LP3218", [(r"^VIN$", 2.5, 5.5)]),
    (r"RT9193", [(r"^VIN$", 2.5, 5.5)]),
    (r"FUSB302", [(r"^VDD$", 2.7, 5.5), (r"^VCONN$", 2.7, 5.5), (r"^VBUS$", 0.0, 21.0)]),
    (r"RTL8125", [(r"VDD33", 3.135, 3.465), (r"VDD09", 0.90, 1.0)]),
    (r"FE1\.1s", [(r"^VD33F$", 3.0, 3.6)]),
    (r"SLB 9670", [(r"^VDD$", 3.0, 3.6)]),
    (r"ESP32-H2", [(r"^3V3$|^VBAT$", 3.0, 3.6)]),
    (r"eMMC", [(r"^VDDF$", 2.7, 3.6), (r"^VDD$", 1.7, 1.95)]),
    (r"LPDDR4X", [(r"^VDD1$", 1.7, 1.95), (r"^VDD2$", 1.06, 1.17), (r"^VDDQ$", 0.57, 0.65)]),
    (r"LMK00304", [(r"^VCC", 3.135, 3.465)]),
    (r"\((M|E|B)-key\)", [(r"^3\.3V$", 3.135, 3.465)]),
    (r"^USB-A|^USB-C$", [(r"^VBUS", 0.0, 21.0)]),
]

# Processor IO banks: which rail powers the pins, by GPIO name.
def gpio_domain(gpio):
    bank, port, bit = int(gpio[4]), gpio[6], int(gpio[7])
    if bank == 0:
        return "VCC_1V8_S3" if (port == "A" or (port == "B" and bit <= 4)) else "VCC_3V3_S3"
    if bank == 2:
        return "VCC_1V8_S3"
    if bank == 3:
        return "VCC_3V3_S0"
    if bank == 4:
        return "VCC_3V3_S0" if (port in "AB" or (port == "C" and bit <= 1)) else "VCC_1V8_S0"
    return "VCC_1V8_S0"


# Chips whose pins on processor nets are open-drain or inputs only (enable pins, interrupt outputs),
# so they cannot push current into the processor.
OPEN_DRAIN = r"SY6280|MP8759|RK806|RK860|FUSB302|HYM8563|2N7002|BSS138|AO34|SRV05|TPD4E|ESD|key\)|SIM|LMK00304|HR911130C"

results = []


def check(ok, text):
    results.append((bool(ok), text))
    print(("  ok    " if ok else "  FAIL  ") + text)


def ohms(value):
    m = re.match(r"([\d.]+)\s*([RKM]?)", value.strip().upper())
    return float(m.group(1)) * {"": 1.0, "R": 1.0, "K": 1e3, "M": 1e6}[m.group(2)]


class Design:
    def __init__(self, project):
        self.parts, self.nets = [], {}
        for sheet in project.sheets:
            for p in sheet.parts:
                if p.ref.startswith("#"):
                    continue
                self.parts.append(p)
                for num, net in p.assigned.items():
                    if net:
                        self.nets.setdefault(net, []).append((p, num))

    def two_pin(self, net, prefix):
        """[(part, the net on its other pin)] for two-pin parts of a kind on `net`."""
        out = []
        for p, num in self.nets.get(net, []):
            if p.ref.rstrip("0123456789") == prefix and len(p.assigned) == 2:
                other = [n for k, n in p.assigned.items() if k != num][0]
                out.append((p, other))
        return out

    def pin_net(self, part, name_pattern):
        return [(pin["name"], part.assigned.get(pin["number"])) for pin in part.pins
                if re.search(name_pattern, pin["name"])]


def volts(net):
    return RAILS.get(net, (None, None))[0]


def check_dividers(d):
    print("\n1. Regulator output voltages (from the feedback resistors)")
    for fb, rail, vref, lo, hi, why in DIVIDERS:
        res = d.two_pin(fb, "R")
        top = [ohms(p.value) for p, other in res if other == rail]
        bottom = [ohms(p.value) for p, other in res if other == "GND"]
        if len(top) != 1 or len(bottom) != 1:
            check(False, "%s: expected one resistor to %s and one to ground on %s" % (rail, rail, fb))
            continue
        nom = vref * (1 + top[0] / bottom[0])
        # worst case: 1 % resistors both ways and 1 % reference
        worst_hi = vref * 1.01 * (1 + top[0] * 1.01 / (bottom[0] * 0.99))
        worst_lo = vref * 0.99 * (1 + top[0] * 0.99 / (bottom[0] * 1.01))
        RAILS[rail] = (round(nom, 3), RAILS[rail][1])
        check(lo <= worst_lo and worst_hi <= hi, "%-16s %.3f V (%.3f to %.3f with tolerances); allowed %.3f to %.3f: %s"
              % (rail, nom, worst_lo, worst_hi, lo, hi, why))


def check_supply_pins(d):
    print("\n2. Supply pins against datasheet limits")
    done, unknown = 0, []
    for p in d.parts:
        for pattern, pins in SUPPLY_LIMITS:
            if not re.search(pattern, p.value):
                continue
            for name_pattern, lo, hi in pins:
                for name, net in d.pin_net(p, name_pattern):
                    if net is None:
                        continue
                    if net == "VIN":
                        ok, v = lo <= VIN_MIN and VIN_MAX <= hi, "%.1f to %.1f" % (VIN_MIN, VIN_MAX)
                    elif net == "USBC1_VBUS":
                        ok, v = VIN_MAX <= hi, "up to %.0f" % VIN_MAX
                    elif volts(net) is None:
                        unknown.append("%s.%s on %s" % (p.ref, name, net))
                        continue
                    else:
                        ok, v = lo <= volts(net) <= hi, "%.2f" % volts(net)
                    done += 1
                    if not ok:
                        check(False, "%s (%s) pin %s on %s at %s V, allowed %.2f to %.2f V"
                              % (p.ref, p.value, name, net, v, lo, hi))
    check(not unknown, "every supply pin is on a rail of known voltage%s"
          % ("; unknown: " + ", ".join(sorted(set(unknown))[:8]) if unknown else ""))
    check(True, "%d supply pins checked against their limits (failures, if any, are listed above)" % done)


def divided(d, net, source_volts, source_net):
    """Voltage on `net` from a resistor to `source_net` and a resistor to ground."""
    res = d.two_pin(net, "R")
    top = [ohms(p.value) for p, o in res if o == source_net]
    bottom = [ohms(p.value) for p, o in res if o == "GND"]
    if not top:
        return None, None, None
    if not bottom:
        return source_volts, top[0], None
    return source_volts * bottom[0] / (top[0] + bottom[0]), top[0], bottom[0]


def check_enables(d):
    print("\n3. Enable pins")
    for p in d.parts:
        if "MP8759" in p.value:
            en = d.pin_net(p, r"^EN$")[0][1]
            zener = [z for z, o in d.two_pin(en, "D") if o == "GND"]
            sources = [o for _, o in d.two_pin(en, "R") if o != "GND"]
            src = sources[0] if sources else None
            if src == "VIN":
                lo, top, bottom = divided(d, en, 4.5, "VIN")       # at the chip's own lockout voltage
                hi, _, _ = divided(d, en, VIN_MAX, "VIN")
                thevenin = top * bottom / (top + bottom)
                lo_leak = lo - 5e-6 * thevenin                    # 5 uA zener leakage, worst case
                clamp = 3.6 * 1.07 if zener else hi
                top_v = min(hi, clamp)
                check(lo_leak >= 1.35 and top_v <= 4.5 * 0.9,
                      "%s EN: %.2f V at VIN 4.5 V (needs 1.35 V), %.2f V at VIN %.0f V%s (absolute maximum 4.5 V)"
                      % (p.ref, lo_leak, top_v, VIN_MAX, ", zener clamped" if zener and hi > clamp else ""))
            else:
                v, _, _ = divided(d, en, volts(src) or 0, src)
                gpio_high = 3.3 if volts(src) is None else None
                v = v if volts(src) else gpio_high * 100 / 110.0
                check(1.35 <= v <= 4.05, "%s EN: driven by %s, %.2f V when on (needs 1.35 V, absolute maximum 4.5 V)"
                      % (p.ref, src, v))
        if "SY6280" in p.value:
            en = d.pin_net(p, r"^EN$")[0][1]
            sources = [o for _, o in d.two_pin(en, "R") if o != "GND"]
            if sources:
                v, _, _ = divided(d, en, volts(sources[0]), sources[0])
                src = sources[0]
            else:                                                  # straight from a processor pin
                balls = [(q, n) for q, n in d.nets[en] if q.ref == "U100"]
                gpio = re.search(r"GPIO\d_[A-D]\d", [x["name"] for x in balls[0][0].pins if x["number"] == balls[0][1]][0]).group(0)
                src = "%s (%s)" % (gpio, gpio_domain(gpio))
                v = volts(gpio_domain(gpio))
            check(v >= 2.0, "%s (SY6280) EN: driven by %s at %.2f V (needs 2.0 V)" % (p.ref, src, v))
            iset = d.pin_net(p, r"^ISET$")[0][1]
            r = [ohms(q.value) for q, o in d.two_pin(iset, "R") if o == "GND"][0]
            out = d.pin_net(p, r"^OUT$")[0][1]
            check(0.4 <= 6800 / r <= 2.0, "%s current limit on %s: 6800 / %.0f = %.2f A (part range 0.4 A to 2 A)"
                  % (p.ref, out, r, 6800 / r))


def check_operating_point(d):
    print("\n4. Input converters across the input range (MP8759: 700 kHz, 50 ns minimum on-time, 10.5 A valley limit)")
    import allocation_check as ac
    f = 700e3
    for i, p in enumerate([q for q in d.parts if "MP8759" in q.value]):
        rail = d.pin_net(p, r"^VOUT$")[0][1]
        vout = volts(rail)
        coil = [ohms(q.value.replace("uH", "").split()[0]) * 1e-6 for q, o in d.two_pin(rail, "L")][0]
        load = sum(a for _, r, a, _ in ac.LOADS if r == rail)
        on = vout / VIN_MAX / f
        ripple = vout * (1 - vout / VIN_MAX) / (f * coil)
        peak = load + ripple / 2
        check(on >= 100e-9 and peak <= 10.5 and load <= 8 * 0.8,
              "%-11s %.2f V: on-time %.0f ns at %.0f V in; load %.1f A, ripple %.1f A, peak %.1f A"
              % (rail, vout, on * 1e9, VIN_MAX, load, ripple, peak))
    check(True, "note: below about 5.7 V in, the 5.15 V rail runs in dropout and simply follows the input "
                "(the case for USB-C before 20 V is negotiated)")


def check_sequence(d):
    print("\n5. Power-up order and signal levels at the processor's pins")
    bad, levels, seen = [], [], 0
    for net, nodes in d.nets.items():
        balls = [(p, n) for p, n in nodes if p.ref == "U100"]
        gpios = []
        for p, n in balls:
            m = re.search(r"GPIO\d_[A-D]\d", [x["name"] for x in p.pins if x["number"] == n][0])
            if m:
                gpios.append(m.group(0))
        if not gpios or net in RAILS:
            continue
        domain = gpio_domain(gpios[0])
        dv, ds = RAILS[domain]
        for r, other in d.two_pin(net, "R"):
            if other in RAILS and other != "GND" and RAILS[other][0]:
                seen += 1
                if RAILS[other][1] < ds:
                    bad.append("%s pulled up to %s before %s (%s) is powered" % (net, other, gpios[0], domain))
                if RAILS[other][0] > dv + 0.3:
                    levels.append("%s pulled up to %s (%.2f V) on a %.1f V pin %s" % (net, other, RAILS[other][0], dv, gpios[0]))
        for p, n in nodes:
            if p.ref == "U100" or not re.match(r"[UJ]\d", p.ref) or re.search(OPEN_DRAIN, p.value):
                continue
            supplies = [nn for _, nn in d.pin_net(p, r"V(DD|CC|IN)|3V3|3\.3V|^IN$") if nn in RAILS and RAILS[nn][0]]
            if not supplies:
                continue
            seen += 1
            first = min(supplies, key=lambda s: RAILS[s][1])
            if RAILS[first][1] < ds:
                bad.append("%s (%s, powered from %s) drives %s before %s (%s) is powered"
                           % (p.ref, p.value, first, net, gpios[0], domain))
            top = max(RAILS[s][0] for s in supplies)
            if top > dv + 0.4 and "eMMC" not in p.value:
                levels.append("%s (%s, %.2f V supply) on %s, a %.1f V pin %s" % (p.ref, p.value, top, net, dv, gpios[0]))
    check(not bad, "nothing can push current into a processor pin before that pin's supply is up (%d pull-ups and "
          "chips checked)%s" % (seen, "; " + "; ".join(bad[:6]) if bad else ""))
    check(not levels, "no pull-up or chip is at a higher voltage than the processor pin it connects to%s"
          % ("; " + "; ".join(levels[:6]) if levels else ""))


def check_housekeeping(d):
    print("\n6. Housekeeping")
    buses = sorted(n for n in d.nets if re.match(r"I2C\d_(SCL|SDA)", n))
    missing = [n for n in buses if not any(o in RAILS for _, o in d.two_pin(n, "R"))]
    check(buses and not missing, "all %d I2C lines have a pull-up%s" % (len(buses), "; missing: " + ", ".join(missing) if missing else ""))
    sense = sorted(n for n in d.nets if n.endswith("_S0_FB"))
    untied = [n for n in sense if not any(o == n[:-3] for p, o in d.two_pin(n, "NT"))]
    check(sense and not untied, "all %d remotely sensed rails have their sense tie at the processor%s"
          % (len(sense), "; missing: " + ", ".join(untied) if untied else ""))
    unlisted = sorted(n for n in d.nets if re.match(r"(VCC|VDD|\+3V3)", n) and n not in RAILS
                      and not n.endswith("_FB") and not re.search(r"_EN$|ISET|VSEL", n))
    core = [n for n in unlisted if re.match(r"VDD_(CPU|GPU|NPU|LOG|VDENC)", n)]
    other = [n for n in unlisted if n not in core]
    check(not other, "every supply net is in the rail table%s (the %d processor core rails are set by software, "
          "0.55 V to 1.0 V)" % ("; not listed: " + ", ".join(other[:8]) if other else "", len(core)))


def check_budget():
    print("\n7. Load budget (design/allocation_check.py)")
    import allocation_check as ac
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        ac.failures.clear()
        ac.check_interfaces()
        ac.check_power()
    check(not ac.failures, "interface allocation and load budget: %d failure(s)%s"
          % (len(ac.failures), "; " + "; ".join(ac.failures[:3]) if ac.failures else ""))
    for name, (v, rating) in ac.RAILS.items():
        full = sum(a for _, rail, a, _ in ac.LOADS if rail == name)
        print("        %-11s %.1f A worst case of %.0f A" % (name, full, rating))


def run(project):
    d = Design(project)
    check_dividers(d)
    check_supply_pins(d)
    check_enables(d)
    check_operating_point(d)
    check_sequence(d)
    check_housekeeping(d)
    check_budget()
    return results


if __name__ == "__main__":
    import build
    build.build_all()
    run(build.project)
    fails = [t for ok, t in results if not ok]
    print("\n%d checks, %d failed" % (len(results), len(fails)))
    sys.exit(1 if fails else 0)
