"""Minimal KiCad board writer (standard library only).

Loads footprints, places them, assigns nets to pads from the schematic generator's
pin-to-net table, and writes a .kicad_pcb in an older, well-known file format.
Run `kicad-cli pcb upgrade` on the result to convert it to the installed KiCad's
native format. This writes placement only: no tracks, no zones.
"""
import copy
import math
import os

import kicadgen as kg
from kicadgen import Q

# Stock KiCad footprints: KICAD_FOOTPRINT_DIR overrides; else the Linux package path; else macOS.
STOCK = os.environ.get("KICAD_FOOTPRINT_DIR") or next(
    (d for d in ("/usr/share/kicad/footprints",) if os.path.isdir(d)),
    "/Applications/KiCad/KiCad.app/Contents/SharedSupport/footprints")
_cache = {}


def load_footprint(fp_id, project_dir):
    """Parsed footprint for 'Lib:Name' (stock library, or the project's own 'hookprobe' library)."""
    if fp_id not in _cache:
        lib, name = fp_id.split(":")
        base = os.path.join(project_dir, lib + ".pretty") if lib == kg.LIB else os.path.join(STOCK, lib + ".pretty")
        with open(os.path.join(base, name + ".kicad_mod"), encoding="utf-8") as fh:
            tree = kg.parse(fh.read())
        if tree[0] == "kicad_footprint_lib":       # newer KiCad wraps the footprint in a one-entry library
            tree = kg.find(tree, "footprint")
        _cache[fp_id] = tree
    return _cache[fp_id]


def _xy(node, key):
    c = kg.find(node, key)
    return (float(c[1]), float(c[2])) if c else None


def extent(fp):
    """(xmin, ymin, xmax, ymax) of the courtyard, falling back to the pads, in footprint coordinates."""
    pts = []
    for item in fp:
        if not isinstance(item, list):
            continue
        layer = kg.find(item, "layer")
        if item[0] in ("fp_line", "fp_rect", "fp_circle", "fp_poly", "fp_arc") and layer and "CrtYd" in str(layer[1]):
            for key in ("start", "end", "mid", "center"):
                p = _xy(item, key)
                if p:
                    pts.append(p)
            poly = kg.find(item, "pts")
            if poly:
                pts += [(float(c[1]), float(c[2])) for c in kg.find_all(poly, "xy")]
            if item[0] == "fp_circle":
                c, e = _xy(item, "center"), _xy(item, "end")
                r = math.hypot(e[0] - c[0], e[1] - c[1])
                pts += [(c[0] - r, c[1] - r), (c[0] + r, c[1] + r)]
    # Always include the pads too: some vendor footprints have no courtyard, or one smaller than
    # their pads. A pad may be rotated, so take its larger dimension both ways, plus a small margin.
    for pad in kg.find_all(fp, "pad"):
        (x, y), (w, h) = _xy(pad, "at"), _xy(pad, "size")
        r = max(w, h) / 2 + 0.15
        pts += [(x - r, y - r), (x + r, y + r)]
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    return min(xs), min(ys), max(xs), max(ys)


def pad_centroid(fp):
    pads = [_xy(p, "at") for p in kg.find_all(fp, "pad")]
    return sum(p[0] for p in pads) / len(pads), sum(p[1] for p in pads) / len(pads)


def rotate(x, y, deg):
    """Footprint-local point to board offset for a footprint rotated `deg` (KiCad's sense, y down)."""
    a = math.radians(deg)
    return x * math.cos(a) + y * math.sin(a), -x * math.sin(a) + y * math.cos(a)


def rotated_extent(ext, deg):
    corners = [rotate(x, y, deg) for x in (ext[0], ext[2]) for y in (ext[1], ext[3])]
    xs, ys = [c[0] for c in corners], [c[1] for c in corners]
    return min(xs), min(ys), max(xs), max(ys)


def _fmt(v):
    return kg._fmt(v)


def _swap_side(name):
    name = str(name)
    if name.startswith("F."):
        return Q("B." + name[2:])
    if name.startswith("B."):
        return Q("F." + name[2:])
    return Q(name)


def mirror(node):
    """Flip a footprint to the back of the board in place: mirror left-right and swap F/B layers."""
    if not isinstance(node, list) or not node:
        return
    head = node[0]
    if head in ("at", "start", "end", "mid", "center", "xy", "offset") and len(node) > 2 and not isinstance(node[1], list):
        node[1] = _fmt(-float(node[1]))
        if head == "at" and len(node) > 3:
            node[3] = _fmt((-float(node[3])) % 360)
    elif head in ("layer", "layers"):
        node[1:] = [_swap_side(n) for n in node[1:]]
    elif head == "effects":                       # text on the back reads correctly only when mirrored
        just = kg.find(node, "justify")
        if just is None:
            node.append(["justify", "mirror"])
        elif "mirror" not in just:
            just.append("mirror")
    for child in node:
        mirror(child)


def _repair_unnamed_pads(fp):
    """Fix two habits of vendor (LCSC) footprints that fail a manufacturing check.

    - Locating-peg holes drawn as plated pads with no copper ring: make them plain non-plated holes.
    - Thermal vias inside an exposed pad drawn as separate unnamed pads: give them the exposed pad's
      number, so they are on its net.
    """
    pads = kg.find_all(fp, "pad")
    named = [(q, _xy(q, "at"), _xy(q, "size")) for q in pads if str(q[1]).strip('"') and q[2] == "smd"]
    for pad in pads:
        if str(pad[1]).strip('"') or pad[2] != "thru_hole":
            continue
        drill = kg.find(pad, "drill")
        hole = max(float(v) for v in drill[1:] if str(v).replace(".", "").isdigit())
        (x, y), (w, h) = _xy(pad, "at"), _xy(pad, "size")
        if min(w, h) <= hole + 0.01:
            pad[2] = "np_thru_hole"
            continue
        for q, (qx, qy), (qw, qh) in named:
            if abs(x - qx) <= qw / 2 and abs(y - qy) <= qh / 2:
                pad[1] = q[1]
                break


class Board:
    def __init__(self, project_dir, width, height, copper_layers=8):
        self.project_dir, self.width, self.height = project_dir, width, height
        self.copper_layers = copper_layers
        self.nets = {"": 0}
        self.items = []
        self.placed = {}          # ref -> (x, y, rot, board extent, back)
        self.holes = []           # (ref, box) of every through-hole pad and hole, in board coordinates

    def net(self, name):
        if name not in self.nets:
            self.nets[name] = len(self.nets)
        return self.nets[name]

    def place(self, ref, value, fp_id, pins, x, y, rot=0, back=False, fields=None, board_only=False):
        """Add a footprint at (x, y); `pins` maps pad number -> net name (None = unconnected).

        `fields` are extra symbol fields copied onto the footprint; `board_only` marks parts such as
        mounting holes that have no schematic symbol.
        """
        fp = copy.deepcopy(load_footprint(fp_id, self.project_dir))
        if fields is None:
            fields = getattr(self, "fields", {}).get(ref, {})
        for name, val in (fields or {}).items():
            fp.append(["property", Q(name), Q(val), ["at", "0", "0", "0"], ["layer", Q("F.Fab")], ["hide", "yes"],
                       ["effects", ["font", ["size", "1", "1"], ["thickness", "0.15"]]]])
        if board_only:
            attr = kg.find(fp, "attr")
            if attr is None:
                fp.append(["attr", "board_only"])
            elif "board_only" not in attr:
                attr.append("board_only")
        _repair_unnamed_pads(fp)
        for pad in kg.find_all(fp, "pad"):
            if pad[2] in ("thru_hole", "np_thru_hole"):
                (px, py), (w, h) = _xy(pad, "at"), _xy(pad, "size")
                if back:
                    px = -px
                dx, dy = rotate(px, py, rot)
                r = max(w, h) / 2
                self.holes.append((ref, (x + dx - r, y + dy - r, x + dx + r, y + dy + r)))
        if back:
            for item in fp[2:]:
                mirror(item)
        out = ["footprint", Q(fp_id), ["layer", Q("B.Cu" if back else "F.Cu")], ["uuid", kg.uid("fp:" + ref)],
               ["at", _fmt(x), _fmt(y)] + ([_fmt(rot)] if rot else [])]
        for item in fp[2:]:
            if not isinstance(item, list) or item[0] in ("version", "generator", "generator_version", "layer", "uuid", "at"):
                continue
            if item[0] == "property" and str(item[1]) in ("Reference", "Value"):
                item[2] = Q(ref if str(item[1]) == "Reference" else value)
            if item[0] in ("property", "fp_text", "pad") and rot:
                at = kg.find(item, "at")
                if at is not None:
                    angle = float(at[3]) if len(at) > 3 else 0.0
                    at[3:] = [_fmt((angle + rot) % 360)]
            if item[0] == "zone":
                # zones inside a footprint are stored in board coordinates: move them with the part
                poly = kg.find(item, "polygon")
                for xy in kg.find_all(kg.find(poly, "pts"), "xy") if poly else []:
                    dx, dy = rotate(float(xy[1]), float(xy[2]), rot)
                    xy[1], xy[2] = _fmt(x + dx), _fmt(y + dy)
            if item[0] == "pad":
                name = pins.get(str(item[1]))
                if name:
                    item.append(["net", str(self.net(name)), Q(name)])
            out.append(item)
        self.items.append(out)
        ext = rotated_extent(extent(fp), rot)
        self.placed[ref] = (x, y, rot, (x + ext[0], y + ext[1], x + ext[2], y + ext[3]), back)

    def text(self, string, x, y, size=1.5, layer="F.SilkS"):
        self.items.append(["gr_text", Q(string), ["at", _fmt(x), _fmt(y)], ["layer", Q(layer)],
                           ["uuid", kg.uid("txt:%s:%s:%s" % (string, x, y))],
                           ["effects", ["font", ["size", str(size), str(size)], ["thickness", "0.2"]],
                            ["justify", "left", "top"]]])

    def rect(self, x0, y0, x1, y1, layer, width=0.1):
        self.items.append(["gr_rect", ["start", _fmt(x0), _fmt(y0)], ["end", _fmt(x1), _fmt(y1)],
                           ["stroke", ["width", str(width)], ["type", "default"]], ["fill", "none"],
                           ["layer", Q(layer)], ["uuid", kg.uid("rect:%s:%s:%s:%s:%s" % (layer, x0, y0, x1, y1))]])

    def write(self, path):
        layers = [["0", Q("F.Cu"), "signal"]]
        layers += [[str(i), Q("In%d.Cu" % i), "signal"] for i in range(1, self.copper_layers - 1)]
        layers += [["31", Q("B.Cu"), "signal"]]
        for num, name in ((32, "B.Adhes"), (33, "F.Adhes"), (34, "B.Paste"), (35, "F.Paste"), (36, "B.SilkS"),
                          (37, "F.SilkS"), (38, "B.Mask"), (39, "F.Mask"), (40, "Dwgs.User"), (41, "Cmts.User"),
                          (44, "Edge.Cuts"), (45, "Margin"), (46, "B.CrtYd"), (47, "F.CrtYd"), (48, "B.Fab"),
                          (49, "F.Fab")):
            layers.append([str(num), Q(name), "user"])
        self.rect(0, 0, self.width, self.height, "Edge.Cuts", 0.15)
        tree = ["kicad_pcb", ["version", "20240108"], ["generator", Q("pcbnew")], ["generator_version", Q("8.0")],
                ["general", ["thickness", "1.6"]], ["paper", Q("A3")], ["layers"] + layers]
        tree += [["net", str(num), Q(name)] for name, num in sorted(self.nets.items(), key=lambda kv: kv[1])]
        tree += self.items
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(kg.dump(tree) + "\n")


def shelf_pack(sizes, width, gap=0.4):
    """Pack rectangles (w, h) left to right in rows no wider than `width`.

    Returns ([(x, y) of each rectangle's top-left corner], total height).
    """
    out, x, y, row_h = [], 0.0, 0.0, 0.0
    for w, h in sizes:
        if x > 0 and x + w > width:
            x, y, row_h = 0.0, y + row_h + gap, 0.0
        out.append((x, y))
        x += w + gap
        row_h = max(row_h, h)
    return out, y + row_h
