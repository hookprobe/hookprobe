#!/usr/bin/env python3
"""Generate the HookProbe SBC rev A board file: outline, layers, every footprint placed, nets assigned.

    python3 schematic/build_pcb.py

This is a FLOORPLAN, not a routed layout. Placement rules used here:
  - Ethernet jacks and the DC jack on the rear edge (top of the drawing), each Ethernet jack on its own.
  - USB-C x2 and the stacked USB-A on the right-hand side edge, in one aligned row.
  - M.2 sockets on the underside along the front edge, cards lying toward the rear.
  - Every chip gets its own resistors, capacitors and inductors clustered tightly around it: a passive
    belongs to the chip in the same schematic sheet that it shares the most signal nets with
    (supply-only parts such as decoupling capacitors go to the chip on that supply).
  - Clusters are grouped into regions: power on the left, processor and memory in the middle,
    Ethernet under its jacks, USB beside its connectors.
Not done: Rockchip's memory layout template, placement of decoupling at specific balls, routing.
"""
import copy
import math
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import build  # noqa: E402  (the schematic generator: the single source of parts and nets)
import kicadgen as kg  # noqa: E402
import pcbgen  # noqa: E402

BOARD_W, BOARD_H = 140.0, 128.0
GAP = 0.3                       # clearance between courtyards
GROUND = {"GND", "GND_CHASSIS"}
PASSIVE_PREFIX = ("R", "C", "L", "FB", "D", "Y", "NT", "F", "Q")

# ALL external ports on the rear edge (top of the drawing), left to right, with their centre x in mm.
# No stacked dual USB-C was found at LCSC, so the two USB-C are single connectors side by side.
EDGE = [("power_entry", "BarrelJack", 19), ("eth1", "RJ45", 40), ("eth2", "RJ45", 59),
        ("usbc1", "USB_C", 74), ("usbc2", "USB_C", 86), ("usb_hub", "USB_A", 103)]

# Cooling: a 40 x 40 mm heatsink-and-fan over the processor and both memory chips. The four 3 mm holes on a
# 38.9 mm square give a 55 mm diagonal, the pattern of the Radxa Heatsink 4012 made for the ROCK 5B
# (5 V fan, 40 x 40 x 12 mm); both diagonals are drilled so either ear orientation fits.
COOLER_CENTRE = (102.0, 60.0)
COOLER_SIZE = 40.0
COOLER_HOLE_HALF = 55.0 / 2 / 2 ** 0.5
# Chips under the cooler, positioned by their centre: (value, dx, dy from the cooler centre, rotation).
UNDER_COOLER = [("RK3588", 0.0, -7.0, 0), ("LPDDR4X 200-ball", -9.0, 10.8, 90), ("LPDDR4X 200-ball", 9.0, 10.8, 90)]
# Sheets whose small parts go on the underside directly beneath the processor and memory.
SOC = ["soc_pcie", "soc_usb", "soc_power", "soc_display", "soc_system", "soc_gpio12", "soc_gpio34", "ddr0", "ddr1"]

# Top-side regions: (x0, y0, x1, y1, [sheets]). Clusters are put in the first free spot, scanning rows
# from the top, avoiding anything already placed, every hole and vent, and the M.2 socket pegs.
# Individual circuits moved out of their sheet's region: (x0, y0, x1, y1, sheet, output rails).
# The M.2 and modem 3.3 V converters go to the open area right of the processor, near the slots they feed,
# which also spreads the heat of the five input converters and is in the cooler fan's airflow.
MOVED = [(106, 82, 124, 114, "power_input", {"VCC_3V3_M2", "VCC_MODEM"}),
         (28, 50, 50, 84, "power_input", {"VCC4V0_SYS"})]      # the 4 V converter sits beside the power chip it feeds
# Order matters: earlier regions get first pick of the space.
#  - each port's circuit directly behind its own connector (ESD parts and series capacitors belong there);
#  - the power chip, then the core regulators, in the column right beside the processor: they carry up to
#    6 A at under 1 V, so every millimetre of distance costs voltage drop and heat;
#  - the eMMC below the cooler, close to the processor's eMMC pins;
#  - the input converters and power entry in the left column, by the DC jack.
REGIONS = [
    (50, 42.5, 81.5, 74, ["pmic"]),
    (54, 72, 81.5, 114, ["core_regs"]),
    (20, 23, 39.5, 50, ["eth1"]), (39.5, 23, 68.2, 42.4, ["eth2"]),
    # the USB-C sockets are only 12 mm deep, so their circuits start right behind them
    (68.3, 13, 83, 34, ["usbc1"]), (68.3, 13, 98.5, 40, ["usbc2"]), (98.5, 18.5, 131, 40, ["usb_hub"]),
    (84, 82, 106, 114, ["emmc"]),
    (26, 84, 57, 114, ["tpm", "core_regs"]),
    (2, 9, 30, 124, ["power_entry", "power_input"]),
    (112, 9, 139, 82, ["peripherals"]),
    (2, 23, 139, 115, None),                                         # anything left over, anywhere free
]
BOTTOM_ONLY = ["pcie_clock", "slots_pcie", "slots_radio"]
FRIENDLY = {"RK3588": "CPU RK3588", "LPDDR4X 200-ball": "RAM LPDDR4X", "eMMC 153-ball": "eMMC",
            "RK806-1": "PMIC", "RTL8125BG-CG": "2.5GbE", "FE1.1s": "USB hub", "SLB 9670VQ2.0": "TPM",
            "ESP32-H2-MINI-1": "Thread/Matter", "HYM8563TS": "RTC", "Au5426 / LMK00304": "PCIe clock",
            "MP8759GD-Z": "input buck", "FUSB302BMPX": "USB-C PD", "LM74700-Q1": "ideal diode"}
# Underside regions (x0, y0, x1, y1, [sheets]), clear of the M.2 cards and the cooler holes.
BOTTOM_REGIONS = [(88, 42, 119, 80, SOC), (113, 86, 139, 120, ["slots_pcie", "slots_radio"]),
                  (124, 30, 139, 84, ["pcie_clock"]), (52, 2, 139, 60, ["pcie_clock", "slots_pcie", "slots_radio"])]
# Underside M.2 sockets along the front edge, cards toward the rear: (value, centre x, card length, width, label).
# Cards face the bottom of the case, so a thermal pad can couple each card to an aluminium base plate.
# Order: the 5G modem at the left edge and Wi-Fi at the right keeps the two radios apart; the two PCIe
# cards sit in the middle, nearer the processor. It also keeps every card standoff out of the column
# beside the processor, which the power chip and core regulators need.
M2 = [("5G modem (B-key)", 20.5, 52, 30, "5G modem 3052"), ("NVMe (M-key)", 47, 80, 22, "NVMe 2280"),
      ("Accelerator (M-key)", 71, 80, 22, "Accelerator 2280"), ("Wi-Fi (E-key)", 100, 30, 22, "Wi-Fi 2230")]
M2_EDGE_Y = BOARD_H - 2
# Case mounting: M3 standoff holes in all four corners, 4 mm in from each edge.
CORNER_HOLES = [(4.0, 4.0), (BOARD_W - 4.0, 4.0), (4.0, BOARD_H - 4.0), (BOARD_W - 4.0, BOARD_H - 4.0)]
# Through-board vent slots (x, y, w, h), placed in areas with no parts on either side.
VENTS = [(x, 76.0, 1.6, 8.0) for x in (126.0, 129.5, 133.0)]


_collected = {}


def collect():
    """{ref: dict(value, fp, pins, sheet)} for every real part, from the schematic generator (built once)."""
    if _collected:
        return _collected
    build.build_all()
    build.project.write()          # also refreshes the project footprint library
    # LCSC footprints come in an old file format; bring the project library up to the installed KiCad's.
    subprocess.run([build.KICAD_CLI, "fp", "upgrade", "--force", os.path.join(HERE, kg.LIB + ".pretty")],
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    parts = {}
    for sheet in build.project.sheets:
        for p in sheet.parts:
            if p.ref.startswith("#"):
                continue
            d = parts.setdefault(p.ref, {"value": p.value, "fp": p.footprint, "pins": {}, "sheet": sheet.name,
                                         "fields": {}})
            d["fields"].update(p.fields)
            d["pins"].update(p.assigned)
            d["fp"] = d["fp"] or p.footprint
    # Use KiCad's own net names (single-sheet nets carry a /sheet path prefix), so the board matches
    # the schematic exactly when KiCad compares them.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        net_file = os.path.join(tmp, "netlist.net")
        subprocess.run([build.KICAD_CLI, "sch", "export", "netlist", "--format", "kicadsexpr", "-o", net_file,
                        os.path.join(HERE, build.project.name + ".kicad_sch")],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tree = kg.parse(open(net_file, encoding="utf-8").read())
    kicad_name = {}
    for net in kg.find_all(kg.find(tree, "nets"), "net"):
        name = str(kg.find(net, "name")[1])
        for node in kg.find_all(net, "node"):
            kicad_name[(str(kg.find(node, "ref")[1]), str(kg.find(node, "pin")[1]))] = name
    for ref, d in parts.items():
        for pin in list(d["pins"]):
            if (ref, pin) in kicad_name:          # includes KiCad's "unconnected-(...)" names
                d["pins"][pin] = kicad_name[(ref, pin)]
    missing = [r for r, d in parts.items() if not d["fp"]]
    if missing:
        raise SystemExit("parts without a footprint: %s" % ", ".join(missing))
    _collected.update(parts)
    return parts


def fp_of(parts, ref, back=False):
    fp = pcbgen.load_footprint(parts[ref]["fp"], HERE)
    if back:
        fp = copy.deepcopy(fp)
        for item in fp[2:]:
            pcbgen.mirror(item)
    return fp


def facing(fp, want):
    """Rotation that turns a connector's opening (pads -> body centre) toward the `want` direction."""
    ext, (px, py) = pcbgen.extent(fp), pcbgen.pad_centroid(fp)
    vx, vy = (ext[0] + ext[2]) / 2 - px, (ext[1] + ext[3]) / 2 - py
    return max((0, 90, 180, 270), key=lambda r: sum(a * b for a, b in zip(pcbgen.rotate(vx, vy, r), want)))


def facing_m2(fp):
    """Rotation for an underside M.2 socket so the card lies toward the rear edge.

    ASSUMPTION, to confirm against the socket drawings: the even-numbered contacts (underside of the
    card) are soldered on the card side of the socket, the odd-numbered ones at its back.
    """
    rows = {0: [], 1: []}
    for pad in kg.find_all(fp, "pad"):
        if str(pad[1]).isdigit() and int(str(pad[1])) <= 75:
            at = kg.find(pad, "at")
            rows[int(str(pad[1])) % 2].append((float(at[1]), float(at[2])))
    ex, ey = (sum(p[i] for p in rows[0]) / len(rows[0]) for i in (0, 1))
    ox, oy = (sum(p[i] for p in rows[1]) / len(rows[1]) for i in (0, 1))
    return max((0, 90, 180, 270), key=lambda r: -pcbgen.rotate(ex - ox, ey - oy, r)[1])


# ------------------------------------------------------------------ clusters --
ATTACHED_PARTS = ("TPD4E05U06",)      # small protection chips: cluster them with their circuit, like passives


def is_passive(ref):
    prefix = ref.rstrip("0123456789")
    if prefix == "U" and ref in _collected and _collected[ref]["value"] in ATTACHED_PARTS:
        return True
    return prefix in PASSIVE_PREFIX


def assign_clusters(parts, refs):
    """Group refs into {anchor ref: [passive refs]}; anchors are the non-passive parts."""
    anchors = [r for r in refs if not is_passive(r)]
    if not anchors:                              # a sheet of passives only: one cluster, biggest part first
        anchors = [max(refs, key=lambda r: area(parts, r))]
    nets_of = {r: set(n for n in parts[r]["pins"].values() if n) - GROUND for r in refs}
    fanout = {}
    for r in refs:
        for n in nets_of[r]:
            fanout[n] = fanout.get(n, 0) + 1
    groups = {a: [] for a in anchors}
    pins_on = {a: {} for a in anchors}
    for a in anchors:
        for n in parts[a]["pins"].values():
            if n:
                pins_on[a][n] = pins_on[a].get(n, 0) + 1
    reach = {a: set(nets_of[a]) for a in anchors}       # nets of the chip and of everything attached so far
    todo = [r for r in refs if r not in groups]
    # Attach the most strongly connected part first, then let the cluster's nets grow through it, so an
    # output capacitor follows its inductor to the right regulator. Widely shared nets count for little.
    while todo:
        best = None
        for r in todo:
            for a in anchors:
                # a chip with several pins on a net (a supply with many decoupling capacitors) pulls harder
                score = sum((1.0 + pins_on[a].get(n, 0)) / fanout[n] for n in nets_of[r] & reach[a])
                key = (round(score, 6), -len(groups[a]))      # ties go to the chip with fewer parts so far
                if score > 0 and (best is None or key > best[0]):
                    best = (key, r, a)
        if best is None:
            break
        _, r, a = best
        groups[a].append(r)
        reach[a] |= nets_of[r]
        todo.remove(r)
    big = max(anchors, key=lambda a: area(parts, a))
    groups[big] += todo
    return groups


def area(parts, ref):
    e = pcbgen.extent(fp_of(parts, ref))
    return (e[2] - e[0]) * (e[3] - e[1])


def overlaps(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def build_cluster(parts, anchor, members, back=False):
    """Lay out one chip and its passives around it. Returns [(ref, dx, dy, rot)] and the cluster extent."""
    placed, boxes = [], []
    e = pcbgen.extent(fp_of(parts, anchor, back))
    placed.append((anchor, 0.0, 0.0, 0))
    boxes.append((e[0] - GAP, e[1] - GAP, e[2] + GAP, e[3] + GAP))
    cx, cy = 0.0, 0.0
    step = 0.25
    for ref in sorted(members, key=lambda r: -area(parts, r)):
        fe = pcbgen.extent(fp_of(parts, ref, back))
        best = None
        for radius in range(0, 400):
            r = radius * step
            n = max(8, int(radius * 2))
            for i in range(n):
                # walk a square ring, not a circle: square clusters pack with far less wasted board
                t = 8.0 * i / n
                side = int(t // 2)
                f = (t - 2 * side) - 1.0
                ux, uy = ((f, -1.0), (1.0, f), (-f, 1.0), (-1.0, -f))[side]
                for rot in (0, 90):
                    ext = pcbgen.rotated_extent(fe, rot)
                    x, y = cx + r * ux, cy + r * uy
                    box = (x + ext[0] - GAP / 2, y + ext[1] - GAP / 2, x + ext[2] + GAP / 2, y + ext[3] + GAP / 2)
                    if not any(overlaps(box, b) for b in boxes):
                        best = (x, y, rot, box)
                        break
                if best:
                    break
            if best:
                break
        placed.append((ref, best[0], best[1], best[2]))
        boxes.append(best[3])
    xs0, ys0 = min(b[0] for b in boxes), min(b[1] for b in boxes)
    xs1, ys1 = max(b[2] for b in boxes), max(b[3] for b in boxes)
    return placed, (xs0, ys0, xs1, ys1)


def obstacles(board, back):
    """Boxes already taken on one side: parts on that side, all holes, vents, and socket pegs or card areas."""
    out = [v[3] for v in board.placed.values() if v[4] == back]
    out += [hb for _, hb in board.holes]
    out += [(x, y, x + w, y + h) for x, y, w, h in VENTS]
    out += board.keepout_back if back else board.keepout_top
    return out


def first_fit(size, region, taken, step=0.5):
    """Top-left-most position for a w x h box inside region that overlaps nothing in `taken`."""
    w, h = size
    x0, y0, x1, y1 = region
    near = [t for t in taken if t[0] < x1 and x0 < t[2] and t[1] < y1 and y0 < t[3]]
    y = y0
    while y + h <= y1 + 1e-6:
        x = x0
        while x + w <= x1 + 1e-6:
            box = (x, y, x + w, y + h)
            hit = next((t for t in near if overlaps(box, t)), None)
            if hit is None:
                return x, y
            x = max(x + step, hit[2] + 0.01)
        y += step
    return None


def place_region(board, parts, refs, region, back=False, label=None):
    """Cluster `refs` round their chips and first-fit the clusters into `region`; returns refs left over."""
    groups = assign_clusters(parts, refs)
    clusters = [build_cluster(parts, a, m, back) for a, m in groups.items()]
    clusters.sort(key=lambda c: -((c[1][2] - c[1][0]) * (c[1][3] - c[1][1])))
    taken = obstacles(board, back)
    left = []
    if label:
        board.text(label, region[0], region[1] - 1.5, 0.8, "Cmts.User")
    for placed, ext in clusters:
        size = (ext[2] - ext[0] + 0.4, ext[3] - ext[1] + 0.4)
        spot = first_fit(size, region, taken)
        if spot is None:
            left += [r for r, *_ in placed]
            continue
        ox, oy = spot[0] + 0.2 - ext[0], spot[1] + 0.2 - ext[1]
        for ref, dx, dy, rot in placed:
            d = parts[ref]
            board.place(ref, d["value"], d["fp"], d["pins"], ox + dx, oy + dy, rot, back=back)
        taken.append((spot[0], spot[1], spot[0] + size[0], spot[1] + size[1]))
    return left


def place_plain(board, parts, refs, region, back=False):
    """First-fit refs one by one (no clustering), tallest first; returns refs left over."""
    def size(ref):
        e = pcbgen.extent(fp_of(parts, ref))
        return e[2] - e[0] + GAP, e[3] - e[1] + GAP
    taken = obstacles(board, back)
    left = []
    for ref in sorted(refs, key=lambda r: (-size(r)[1], parts[r]["fp"], r)):
        spot = first_fit(size(ref), region, taken, 0.25)
        if spot is None:
            left.append(ref)
            continue
        e = pcbgen.extent(fp_of(parts, ref, back))
        d = parts[ref]
        board.place(ref, d["value"], d["fp"], d["pins"], spot[0] + GAP / 2 - e[0], spot[1] + GAP / 2 - e[1], back=back)
        w, h = size(ref)
        taken.append((spot[0], spot[1], spot[0] + w, spot[1] + h))
    return left


def place_at(board, parts, ref, cx, cy, rot=0, back=False):
    """Place a part with its body centred on (cx, cy)."""
    e = pcbgen.rotated_extent(pcbgen.extent(fp_of(parts, ref, back)), rot)
    d = parts[ref]
    board.place(ref, d["value"], d["fp"], d["pins"], cx - (e[0] + e[2]) / 2, cy - (e[1] + e[3]) / 2, rot, back=back)


# ---------------------------------------------------------------------- main --
def main():
    parts = collect()
    board = pcbgen.Board(HERE, BOARD_W, BOARD_H, copper_layers=8)
    board.keepout_top, board.keepout_back = [], []
    board.fields = {r: d["fields"] for r, d in parts.items()}
    todo = set(parts)

    # 1. every external port on the rear edge, openings facing out
    for sheet, text, pos in EDGE:
        ref = next(r for r in sorted(todo) if parts[r]["sheet"] == sheet and text in parts[r]["fp"])
        fp = fp_of(parts, ref)
        rot = facing(fp, (0.0, -1.0))
        ext = pcbgen.rotated_extent(pcbgen.extent(fp), rot)
        d = parts[ref]
        board.place(ref, d["value"], d["fp"], d["pins"], pos - (ext[0] + ext[2]) / 2, -ext[1], rot)
        todo.discard(ref)

    # 2. processor and memory together under one 40 x 40 mm cooler, with its mounting holes
    cx, cy = COOLER_CENTRE
    for value, dx, dy, rot in UNDER_COOLER:
        ref = next(r for r in sorted(todo) if parts[r]["value"] == value)
        place_at(board, parts, ref, cx + dx, cy + dy, rot)
        todo.discard(ref)
    half = COOLER_SIZE / 2
    board.rect(cx - half, cy - half, cx + half, cy + half, "Dwgs.User")
    board.keepout_top.append((cx - half, cy - half, cx + half, cy + half))   # only CPU and RAM under the heatsink
    board.text("40x40 heatsink + 5 V fan (e.g. Radxa Heatsink 4012), thermal pad over CPU and both RAM chips",
               cx - half, cy + half + 0.8, 0.8, "Dwgs.User")
    for i, (sx, sy) in enumerate(((-1, -1), (1, 1), (1, -1), (-1, 1))):
        board.place("H%d" % (i + 1), "Cooler M2.5", "MountingHole:MountingHole_2.7mm_M2.5", {},
                    cx + sx * COOLER_HOLE_HALF, cy + sy * COOLER_HOLE_HALF, board_only=True)
    fan = next(r for r in todo if parts[r]["value"] == "Fan 5 V")
    place_at(board, parts, fan, cx + half + 4.0, cy - 6.0, 90)
    todo.discard(fan)

    # 3. Thread radio module on the right-hand edge, antenna end toward the edge
    mod = next(r for r in todo if "WIFIM" in parts[r]["fp"])
    ext = pcbgen.extent(fp_of(parts, mod))
    board.place(mod, parts[mod]["value"], parts[mod]["fp"], parts[mod]["pins"], BOARD_W - 1 - ext[2], 84 - ext[1])
    board.text("Thread antenna: confirm antenna end at the board edge, no copper under it", BOARD_W - 34, 82, 0.8,
               "Cmts.User")
    todo.discard(mod)

    # 4. board mounting holes and through-board vent slots
    for i, (x, y) in enumerate(CORNER_HOLES):
        board.place("H%d" % (i + 5), "M3", "MountingHole:MountingHole_3.2mm_M3_Pad_Via", {"1": "GND"}, x, y,
                    board_only=True)
    for x, y, w, h in VENTS:
        board.rect(x, y, x + w, y + h, "Edge.Cuts", 0.1)

    # 5. underside: M.2 sockets, their card outlines and the card hold-down screw positions
    for value, mx, card_len, card_w, label in M2:
        ref = next(r for r in todo if parts[r]["value"] == value)
        fp = fp_of(parts, ref, back=True)
        rot = facing_m2(fp)
        ext = pcbgen.rotated_extent(pcbgen.extent(fp), rot)
        y = M2_EDGE_Y - ext[3]
        board.place(ref, parts[ref]["value"], parts[ref]["fp"], parts[ref]["pins"],
                    mx - (ext[0] + ext[2]) / 2, y, rot, back=True)
        top = y + ext[1]
        board.rect(mx - card_w / 2, top - card_len, mx + card_w / 2, top, "Dwgs.User")
        board.keepout_back.append((mx - card_w / 2, top - card_len - 3.0, mx + card_w / 2, top))
        board.keepout_top.append(board.placed[ref][3])          # its pegs go through the board
        board.text(label + ": thermal pad to case base", mx - card_w / 2 + 1, top - card_len + 2, 1.0, "Dwgs.User")
        board.place("H%d" % (len(board.placed) + 100), "M.2 standoff M2",
                    "MountingHole:MountingHole_2.2mm_M2_Pad_Via", {"1": "GND"}, mx, top - card_len - 1.0,
                    board_only=True)
        todo.discard(ref)

    # 7a. circuits moved to their own spot (see MOVED)
    report = []
    for x0, y0, x1, y1, sheet, rails in MOVED:
        refs = [r for r in sorted(todo) if parts[r]["sheet"] == sheet]
        groups = assign_clusters(parts, refs)
        chosen = [r for a, members in groups.items()
                  if rails & set(n.rsplit("/", 1)[-1] for n in parts[a]["pins"].values() if n)
                  for r in [a] + members]
        left = place_region(board, parts, chosen, (x0, y0, x1, y1), label="%s (%s)" % (sheet, ", ".join(sorted(rails))))
        report.append((sheet + " moved", len(chosen) - len(left), len(left)))
        todo -= set(chosen) - set(left)

    # 7. top side regions (the processor sheets' remaining non-passive parts join the peripherals)
    for x0, y0, x1, y1, sheets in REGIONS:
        if sheets is None:
            refs = [r for r in sorted(todo) if parts[r]["sheet"] not in SOC + BOTTOM_ONLY]
            sheets = ["leftover"]
        else:
            extra = [r for r in todo if parts[r]["sheet"] in SOC and not is_passive(r)] if "peripherals" in sheets else []
            refs = [r for r in sorted(todo) if parts[r]["sheet"] in sheets] + sorted(extra)
        if not refs:
            continue
        left = place_region(board, parts, refs, (x0, y0, x1, y1), label=", ".join(sheets[:3]))
        report.append((sheets[0], len(refs) - len(left), len(left)))
        todo -= set(refs) - set(left)
    # 6. underside: processor and memory small parts beneath the cooler, then the other underside blocks
    for x0, y0, x1, y1, sheets in BOTTOM_REGIONS:
        refs = [r for r in sorted(todo) if parts[r]["sheet"] in sheets and (sheets is not SOC or is_passive(r))]
        if not refs:
            continue
        if sheets is SOC:
            left = place_plain(board, parts, refs, (x0, y0, x1, y1), back=True)
        else:
            left = place_region(board, parts, refs, (x0, y0, x1, y1), back=True)
        board.text(", ".join(sheets[:2]) + " (underside)", x0, y0 - 2.0, 0.8, "Dwgs.User")
        report.append(("U:" + sheets[0], len(refs) - len(left), len(left)))
        todo -= set(refs) - set(left)

    if todo:
        print("NOT PLACED (%d): %s" % (len(todo), ", ".join(sorted(todo))))

    # 8. readable labels on every chip, connector and module (layer User.Drawings / Cmts.User)
    for ref, v in board.placed.items():
        if ref not in parts or is_passive(ref):
            continue
        name = FRIENDLY.get(parts[ref]["value"], parts[ref]["value"])
        x0, y0, x1, y1 = v[3]
        size = 1.6 if (x1 - x0) * (y1 - y0) > 150 else 0.9
        board.text("%s %s" % (ref, name), x0, (y0 + y1) / 2 - size / 2, size, "Dwgs.User" if v[4] else "Cmts.User")

    out = os.path.join(HERE, build.project.name + ".kicad_pcb")
    board.write(out)
    r = subprocess.run([build.KICAD_CLI, "pcb", "upgrade", "--force", out], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, universal_newlines=True)
    print("Board %g x %g mm, %d footprints (%d on the underside), %d nets"
          % (BOARD_W, BOARD_H, len(board.placed), sum(1 for v in board.placed.values() if v[4]), len(board.nets) - 1))
    for name, n, left in report:
        print("  %-14s %4d placed, %d passed on" % (name, n, left))
    boxes = [(ref, v[3]) for ref, v in board.placed.items() if not v[4]]
    clash = [(a, b) for i, (a, ba) in enumerate(boxes) for b, bb in boxes[i + 1:] if overlaps(ba, bb)
             and not (a.startswith("H") and b.startswith("H"))]
    sockets = [(ref, v[3]) for ref, v in board.placed.items() if v[4] and ref in parts
               and parts[ref]["value"] in [m[0] for m in M2]]
    clash += [(a, b) for a, ba in boxes for b, bb in sockets if overlaps(ba, bb)]
    under = [(ref, v[3]) for ref, v in board.placed.items() if v[4]]
    clash += [(a, b) for i, (a, ba) in enumerate(under) for b, bb in under[i + 1:] if overlaps(ba, bb)]
    for ref, hb in board.holes:
        side = board.placed[ref][4]
        clash += [(ref, b) for b, v in board.placed.items() if v[4] != side and b != ref and overlaps(hb, v[3])]
    vents = [(x, y, x + w, y + h) for x, y, w, h in VENTS]
    clash += [("vent", ref) for ref, v in board.placed.items() for vb in vents if overlaps(vb, v[3])]
    # underside parts must not sit under an M.2 card
    cards = []
    for value, mx, card_len, card_w, label in M2:
        sref = next(r for r in parts if parts[r]["value"] == value)
        top = board.placed[sref][3][1]
        cards.append((mx - card_w / 2, top - card_len, mx + card_w / 2, top))
    clash += [("card", ref) for ref, v in board.placed.items() if v[4] and ref in parts
              and parts[ref]["value"] not in [m[0] for m in M2] and any(overlaps(c, v[3]) for c in cards)]
    clash = sorted(set(clash))
    off = [ref for ref, v in board.placed.items() if v[3][0] < -0.01 or v[3][1] < -0.01
           or v[3][2] > BOARD_W + 0.01 or v[3][3] > BOARD_H + 0.01]
    print("  clashes: %d %s" % (len(clash), clash[:12]))
    print("  outside the outline: %d %s" % (len(off), off[:8]))
    print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "upgrade produced no output")


if __name__ == "__main__":
    main()
