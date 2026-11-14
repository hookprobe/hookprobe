"""Minimal KiCad schematic generator (standard library only).

Reads symbols from KiCad's stock libraries, copies the ones used into a
project-local library (so the project is self-contained), places them, and
connects pins by net name using short wire stubs ending in a label or a power
symbol. Every pin of every placed part must be given a net or an explicit
no-connect, otherwise generation fails.

Symbols are stored exactly as the installed KiCad stores them, so the files
are stamped with that build's native format version (FILE_VERSION below).
Use `kicad-cli sch downgrade` to get copies for an older KiCad release.
"""
import copy
import os
import re
import shutil
import uuid

# Stock KiCad symbols: KICAD_SYMBOL_DIR overrides; else the Linux package path; else the macOS app.
SYMBOL_DIR = os.environ.get("KICAD_SYMBOL_DIR") or next(
    (d for d in ("/usr/share/kicad/symbols",) if os.path.isdir(d)),
    "/Applications/KiCad/KiCad.app/Contents/SharedSupport/symbols")
FILE_VERSION = "20261106"       # schematic format written by the installed KiCad 10.99 build
GENERATOR_VERSION = "10.99"
SYMLIB_VERSION = "20251024"     # format of the stock symbol libraries
LIB = "hookprobe"               # nickname of the project-local symbol library
NS = uuid.UUID("6f1d5c1e-2b7a-4a58-9d0e-0b5c3f6a1e11")
SIGNAL_TYPES = ("input", "output", "bidirectional", "tri_state", "open_collector",
                "open_emitter", "unspecified")


class Q(str):
    """A string that was (or must be) quoted in the s-expression."""


def uid(key):
    return Q(str(uuid.uuid5(NS, key)))


# ---------------------------------------------------------------- s-expr --
_TOKEN = re.compile(r'\(|\)|"(?:\\.|[^"\\])*"|[^\s()]+')


def parse(text):
    stack = [[]]
    for tok in _TOKEN.findall(text):
        if tok == "(":
            stack.append([])
        elif tok == ")":
            done = stack.pop()
            stack[-1].append(done)
        elif tok.startswith('"'):
            stack[-1].append(Q(tok[1:-1]))
        else:
            stack[-1].append(tok)
    return stack[0][0]


def dump(node, ind=0):
    if not isinstance(node, list):
        return '"%s"' % node if isinstance(node, Q) else str(node)
    simple = all(not isinstance(c, list) for c in node)
    out = "("
    for i, c in enumerate(node):
        if isinstance(c, list) and not simple:
            out += "\n" + "\t" * (ind + 1) + dump(c, ind + 1)
        else:
            out += (" " if i else "") + dump(c, ind + 1)
    if not simple:
        out += "\n" + "\t" * ind
    return out + ")"


def find(node, key):
    for c in node:
        if isinstance(c, list) and c and c[0] == key:
            return c
    return None


def find_all(node, key):
    return [c for c in node if isinstance(c, list) and c and c[0] == key]


# --------------------------------------------------------------- library --
_lib_cache = {}


def _load_lib(lib):
    if lib not in _lib_cache:
        path = lib if lib.endswith(".kicad_sym") else os.path.join(SYMBOL_DIR, lib + ".kicad_sym")
        with open(path, encoding="utf-8") as fh:
            tree = parse(fh.read())
        _lib_cache[lib] = {s[1]: s for s in find_all(tree, "symbol")}
    return _lib_cache[lib]


def load_symbol(lib, name):
    """Return a flattened copy of a library symbol (derived symbols resolved)."""
    syms = _load_lib(lib)
    if name not in syms:
        raise KeyError("symbol %s not found in %s" % (name, lib))
    sym = copy.deepcopy(syms[name])
    ext = find(sym, "extends")
    if ext is None:
        return sym
    parent = load_symbol(lib, ext[1])
    child_props = {p[1]: p for p in find_all(sym, "property")}
    out = ["symbol", Q(name)]
    for item in parent[2:]:
        if item[0] == "property":
            out.append(child_props.pop(item[1], item))
        elif item[0] == "symbol":
            item[1] = Q(name + item[1][len(parent[1]):])
            out.append(item)
        else:
            out.append(item)
    insert_at = max([i for i, c in enumerate(out) if isinstance(c, list) and c[0] == "property"] or [1]) + 1
    for extra in child_props.values():
        out.insert(insert_at, extra)
        insert_at += 1
    return out


def make_signal_pins_passive(sym):
    """Connector pins carry whatever the mating part drives, so type them passive.

    The stock connector symbols type pins from one side's point of view, which
    makes the rules check report undriven inputs and output conflicts that are
    not real. Power-input pins are left alone so missing supplies are still caught.
    """
    for sub in find_all(sym, "symbol"):
        for p in find_all(sub, "pin"):
            if p[1] in SIGNAL_TYPES:
                p[1] = "passive"


def symbol_pins(sym):
    """List of dicts: number, name, type, x, y, angle, unit, hidden."""
    pins = []
    for sub in find_all(sym, "symbol"):
        unit = int(sub[1].rsplit("_", 2)[1])
        for p in find_all(sub, "pin"):
            at = find(p, "at")
            hide = find(p, "hide")
            pins.append({
                "number": str(find(p, "number")[1]),
                "name": str(find(p, "name")[1]).replace("{slash}", "/"),
                "type": p[1],
                "x": float(at[1]), "y": float(at[2]), "angle": int(float(at[3])),
                "unit": unit,
                "hidden": bool(hide and hide[1] == "yes") or "hide" in p,
            })
    return pins


# ------------------------------------------------------------- schematic --
def _fmt(v):
    s = ("%.4f" % v).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def _font(hide=False, justify=None):
    eff = ["effects", ["font", ["size", "1.27", "1.27"]]]
    if justify:
        eff.append(["justify"] + list(justify))
    if hide:
        eff.append(["hide", "yes"])
    return eff


class Part:
    def __init__(self, sheet, name, ref, value, x, y, unit, sym):
        self.sheet, self.name, self.ref, self.value = sheet, name, ref, value
        self.lib_id = "%s:%s" % (LIB, name)
        self.x, self.y, self.unit = x, y, unit
        self.pins = [p for p in symbol_pins(sym) if p["unit"] in (0, unit)]
        # pins the symbol itself types as "no connect" need no net and no flag
        self.assigned = {p["number"]: None for p in self.pins if p["type"] == "no_connect"}
        self.is_power = find(sym, "power") is not None
        self.prop_at, self.prop_just = {}, {}
        for prop in find_all(sym, "property"):
            at = find(prop, "at")
            self.prop_at[str(prop[1])] = (float(at[1]), float(at[2]), at[3] if len(at) > 3 else "0")
            just = find(find(prop, "effects") or [], "justify")
            if just:
                self.prop_just[str(prop[1])] = just[1:]
        self.footprint, self.fields = "", {}

    def select(self, key):
        """Pins matching a pin number, else a pin name."""
        key = str(key)
        hits = [p for p in self.pins if p["number"] == key]
        if not hits:
            hits = [p for p in self.pins if p["name"] == key]
        if not hits:
            raise KeyError("%s (%s): no pin '%s'" % (self.ref, self.name, key))
        return hits

    def unassigned(self):
        return [p for p in self.pins if p["number"] not in self.assigned]


class Sheet:
    def __init__(self, project, name, filename, title, paper="A3"):
        self.project, self.name, self.filename, self.title, self.paper = project, name, filename, title, paper
        self.uuid = uid("sheetfile:" + filename)
        self.path = None           # instance path, set by Project
        self.page = None
        self.lib_symbols = {}
        self.items = []
        self.parts = []
        self._n = 0
        self._drawn = {}           # (ref, x, y) -> net name, to draw stacked pins once

    def _uid(self, kind):
        self._n += 1
        return uid("%s:%s:%d" % (self.filename, kind, self._n))

    # -- placement -------------------------------------------------------
    def place(self, lib_id, ref, value, x, y, footprint="", fields=None, unit=1, passive=False):
        """Place a symbol. `passive=True` retypes its signal pins as passive (for connectors)."""
        sym = self.project.symbol(lib_id, passive)
        name = str(sym[1])
        if name not in self.lib_symbols:
            emb = copy.deepcopy(sym)
            emb[1] = Q("%s:%s" % (LIB, name))
            self.lib_symbols[name] = emb
        if (ref, unit) in self.project.refs:
            raise ValueError("duplicate reference %s unit %d" % (ref, unit))
        owner = self.project.ref_symbol.setdefault(ref, name)
        if owner != name:
            raise ValueError("reference %s used for both %s and %s" % (ref, owner, name))
        self.project.refs.add((ref, unit))
        part = Part(self, name, ref, value, x, y, unit, sym)
        part.footprint = footprint
        part.fields = dict(fields or {})
        if footprint:
            self.project.footprint_libs.add(footprint.split(":")[0])
        self.parts.append(part)
        return part

    def _stub(self, part, pin, length):
        px, py = part.x + pin["x"], part.y - pin["y"]
        dx, dy = {0: (-1, 0), 180: (1, 0), 90: (0, 1), 270: (0, -1)}[pin["angle"] % 360]
        ex, ey = px + dx * length, py + dy * length
        angle = {(-1, 0): 180, (1, 0): 0, (0, -1): 90, (0, 1): 270}[(dx, dy)]
        return px, py, ex, ey, angle

    def net(self, part, key, name, kind="local", shape="bidirectional", stub=2.54):
        """Connect pin(s), selected by number or name, to a net.

        kind: "local" label, "global" label, or "power" (a power symbol named `name`).
        """
        for pin in part.select(key):
            if pin["number"] in part.assigned:
                raise ValueError("%s pin %s assigned twice" % (part.ref, pin["number"]))
            part.assigned[pin["number"]] = name
            px, py, ex, ey, angle = self._stub(part, pin, stub)
            self.project.nets.setdefault(name, []).append("%s.%s" % (part.ref, pin["number"]))
            spot = (part.ref, round(px, 3), round(py, 3))
            if spot in self._drawn:
                if self._drawn[spot] != name:
                    raise ValueError("%s: stacked pins at one point given different nets" % part.ref)
                continue
            self._drawn[spot] = name
            self.items.append(["wire", ["pts", ["xy", _fmt(px), _fmt(py)], ["xy", _fmt(ex), _fmt(ey)]],
                               ["stroke", ["width", "0"], ["type", "default"]], ["uuid", self._uid("wire")]])
            just = "right" if angle in (180, 270) else "left"
            if kind == "power" and angle in (0, 180):
                # On side pins a power symbol collides with the neighbouring rows, so use a
                # global label of the same name: it joins the same net as the power symbols.
                kind, shape = "global", "passive"
            if kind == "power":
                self.project.pwr_n += 1
                sym = self.place("power:" + name, "#PWR%03d" % self.project.pwr_n, name, ex, ey)
                for p in sym.pins:
                    sym.assigned[p["number"]] = name
            elif kind == "global":
                self.items.append(["global_label", Q(name), ["shape", shape],
                                   ["at", _fmt(ex), _fmt(ey), str(angle)], _font(justify=[just]),
                                   ["uuid", self._uid("glabel")],
                                   ["property", Q("Intersheetrefs"), Q("${INTERSHEET_REFS}"),
                                    ["at", _fmt(ex), _fmt(ey), "0"], _font(hide=True)]])
            else:
                self.items.append(["label", Q(name), ["at", _fmt(ex), _fmt(ey), str(angle)],
                                   _font(justify=[just, "bottom"]), ["uuid", self._uid("label")]])

    def nets(self, part, mapping, kind="local", shape="bidirectional"):
        for key, name in mapping.items():
            self.net(part, key, name, kind=kind, shape=shape)

    def nc(self, part, *keys):
        """Mark pin(s) as deliberately unconnected."""
        for key in keys:
            for pin in part.select(key):
                if pin["number"] in part.assigned:
                    raise ValueError("%s pin %s assigned twice" % (part.ref, pin["number"]))
                part.assigned[pin["number"]] = None
                px, py = part.x + pin["x"], part.y - pin["y"]
                spot = (part.ref, round(px, 3), round(py, 3))
                if spot in self._drawn:
                    continue
                self._drawn[spot] = None
                self.items.append(["no_connect", ["at", _fmt(px), _fmt(py)], ["uuid", self._uid("nc")]])

    def flag(self, name, x, y, kind="local"):
        """Declare that net `name` is driven in a way the rules check cannot see (KiCad PWR_FLAG)."""
        self.project.flg_n += 1
        part = self.place("power:PWR_FLAG", "#FLG%03d" % self.project.flg_n, "PWR_FLAG", x, y)
        self.net(part, "1", name, kind=kind)
        return part

    def text(self, string, x, y, size=1.5):
        # KiCad needs line breaks written as the two characters \n; a raw newline makes
        # the whole sheet fail to load (silently, when it is a sub-sheet).
        string = string.replace("\n", "\\n")
        self.items.append(["text", Q(string), ["exclude_from_sim", "no"],
                           ["at", _fmt(x), _fmt(y), "0"],
                           ["effects", ["font", ["size", str(size), str(size)]], ["justify", "left", "top"]],
                           ["uuid", self._uid("text")]])

    # -- output ----------------------------------------------------------
    def _symbol_node(self, part):
        def prop(name, value, hide):
            ax, ay, rot = part.prop_at.get(name, (0.0, 0.0, "0"))
            return ["property", Q(name), Q(value), ["at", _fmt(part.x + ax), _fmt(part.y - ay), str(rot)],
                    _font(hide=hide, justify=part.prop_just.get(name))]

        hidden_ref = part.ref.startswith("#")
        node = ["symbol", ["lib_id", Q(part.lib_id)], ["at", _fmt(part.x), _fmt(part.y), "0"],
                ["unit", str(part.unit)], ["exclude_from_sim", "no"],
                ["in_bom", "no" if part.name.startswith("NetTie") else "yes"],
                ["on_board", "yes"], ["dnp", "no"], ["uuid", uid("sym:%s:%d" % (part.ref, part.unit))],
                prop("Reference", part.ref, hidden_ref),
                prop("Value", part.value, part.name == "PWR_FLAG"),
                prop("Footprint", part.footprint, True),
                prop("Datasheet", "~", True)]
        for k, v in part.fields.items():
            node.append(prop(k, v, True))
        for p in part.pins:
            node.append(["pin", Q(p["number"]), ["uuid", uid("pin:%s:%d:%s" % (part.ref, part.unit, p["number"]))]])
        node.append(["instances", ["project", Q(self.project.name),
                                   ["path", Q(self.path), ["reference", Q(part.ref)], ["unit", str(part.unit)]]]])
        return node

    def check_complete(self):
        missing = []
        for part in self.parts:
            for p in part.unassigned():
                missing.append("%s pin %s (%s)" % (part.ref, p["number"], p["name"]))
        return missing

    def tree(self, extra=()):
        root = ["kicad_sch", ["version", FILE_VERSION], ["generator", Q("eeschema")],
                ["generator_version", Q(GENERATOR_VERSION)],
                ["uuid", self.uuid], ["paper", Q(self.paper)],
                ["title_block", ["title", Q(self.title)], ["company", Q("HookProbe")], ["rev", Q("A0")]],
                ["lib_symbols"] + list(self.lib_symbols.values())]
        root += self.items
        root += [self._symbol_node(p) for p in self.parts]
        root += list(extra)
        return root


class Project:
    def __init__(self, name, outdir):
        self.name, self.outdir = name, outdir
        self.refs, self.nets, self.pwr_n, self.flg_n = set(), {}, 0, 0
        self.lib, self.lib_passive, self.footprint_libs = {}, {}, set()
        self.ref_symbol, self.local_footprints = {}, []
        self.root = Sheet(self, "root", name + ".kicad_sch", "HookProbe SBC rev A", paper="A4")
        self.root.path = "/" + self.root.uuid
        self.root.page = 1
        self.sheets = []

    def add_symbol(self, sym):
        """Register a project-specific symbol (not from the stock libraries)."""
        self.lib[str(sym[1])] = sym
        self.lib_passive[str(sym[1])] = None

    def add_footprint(self, path):
        """Copy a footprint file into the project-local footprint library."""
        self.local_footprints.append(path)

    def symbol(self, lib_id, passive=False):
        """Fetch a stock symbol into the project library (once) and return it."""
        lib, name = lib_id.split(":")
        if self.lib_passive.get(name, False) is None:
            return self.lib[name]
        if name not in self.lib:
            sym = load_symbol(lib, name)
            if passive:
                make_signal_pins_passive(sym)
            self.lib[name] = sym
            self.lib_passive[name] = passive
        elif self.lib_passive[name] != passive:
            raise ValueError("%s requested both with and without passive pins" % name)
        return self.lib[name]

    def sheet(self, name, title, paper="A3"):
        s = Sheet(self, name, name + ".kicad_sch", title, paper)
        s.sym_uuid = uid("sheetsym:" + name)
        s.path = "/%s/%s" % (self.root.uuid, s.sym_uuid)
        s.page = len(self.sheets) + 2
        self.sheets.append(s)
        return s

    def _write(self, filename, text):
        with open(os.path.join(self.outdir, filename), "w", encoding="utf-8") as fh:
            fh.write(text)

    def write(self):
        missing = []
        for s in self.sheets:
            missing += ["%s: %s" % (s.name, m) for m in s.check_complete()]
        if missing:
            raise SystemExit("Unassigned pins (give each a net or nc):\n  " + "\n  ".join(missing))
        os.makedirs(self.outdir, exist_ok=True)
        boxes = []
        for i, s in enumerate(self.sheets):
            x, y, w, h = 25.4 + (i % 4) * 63.5, 38.1 + (i // 4) * 38.1, 50.8, 25.4
            boxes.append(["sheet", ["at", _fmt(x), _fmt(y)], ["size", _fmt(w), _fmt(h)],
                          ["exclude_from_sim", "no"], ["in_bom", "yes"], ["on_board", "yes"], ["dnp", "no"],
                          ["stroke", ["width", "0.1524"], ["type", "solid"]],
                          ["fill", ["color", "0", "0", "0", "0.0000"]], ["uuid", s.sym_uuid],
                          ["property", Q("Sheetname"), Q(s.title), ["at", _fmt(x), _fmt(y - 0.7), "0"],
                           _font(justify=["left", "bottom"])],
                          ["property", Q("Sheetfile"), Q(s.filename), ["at", _fmt(x), _fmt(y + h + 0.6), "0"],
                           _font(justify=["left", "top"])],
                          ["instances", ["project", Q(self.name),
                                         ["path", Q(self.root.path), ["page", Q(str(s.page))]]]]])
        tail = [["sheet_instances", ["path", Q("/"), ["page", Q("1")]]], ["embedded_fonts", "no"]]
        self._write(self.root.filename, dump(self.root.tree(boxes + tail)) + "\n")
        for s in self.sheets:
            self._write(s.filename, dump(s.tree([["embedded_fonts", "no"]])) + "\n")
        # project-local symbol library and library tables
        lib = ["kicad_symbol_lib", ["version", SYMLIB_VERSION], ["generator", Q("kicad_symbol_editor")],
               ["generator_version", Q("10.0")]] + [self.lib[k] for k in sorted(self.lib)]
        self._write(LIB + ".kicad_sym", dump(lib) + "\n")
        self._write("sym-lib-table",
                    '(sym_lib_table\n\t(version 7)\n\t(lib (name "%s") (type "KiCad") '
                    '(uri "${KIPRJMOD}/%s.kicad_sym") (options "") (descr "HookProbe project symbols"))\n)\n'
                    % (LIB, LIB))
        rows = "".join('\t(lib (name "%s") (type "KiCad") (uri "${KICAD10_FOOTPRINT_DIR}/%s.pretty") '
                       '(options "") (descr ""))\n' % (n, n) for n in sorted(self.footprint_libs - {LIB}))
        if self.local_footprints:
            pretty = os.path.join(self.outdir, LIB + ".pretty")
            os.makedirs(pretty, exist_ok=True)
            for src in self.local_footprints:
                shutil.copyfile(src, os.path.join(pretty, os.path.basename(src)))
            rows += ('\t(lib (name "%s") (type "KiCad") (uri "${KIPRJMOD}/%s.pretty") '
                     '(options "") (descr "HookProbe project footprints"))\n' % (LIB, LIB))
        self._write("fp-lib-table", "(fp_lib_table\n\t(version 7)\n" + rows + ")\n")
        pro = os.path.join(self.outdir, self.name + ".kicad_pro")
        if not os.path.exists(pro):
            self._write(self.name + ".kicad_pro",
                        '{\n  "meta": {\n    "filename": "%s.kicad_pro",\n    "version": 3\n  }\n}\n' % self.name)


if __name__ == "__main__":
    import sys
    lib, name = sys.argv[1].split(":")
    for p in sorted(symbol_pins(load_symbol(lib, name)), key=lambda p: (p["unit"], p["number"].zfill(4))):
        print("%-5s %-28s %-14s unit %d  (%g, %g, %d)%s" % (
            p["number"], p["name"], p["type"], p["unit"], p["x"], p["y"], p["angle"], "  hidden" if p["hidden"] else ""))
