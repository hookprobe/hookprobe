#!/usr/bin/env python3
"""Generate the HookProbe SBC rev A schematic and verify it with KiCad.

    python3 schematic/build.py            # write the .kicad_sch files
    python3 schematic/build.py --verify   # also run the netlist cross-check and ERC

The schematic is generated from this script; edit the script, not the
.kicad_sch files, or the edits are lost on the next run.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import kicadgen as kg  # noqa: E402
import rk3588_symbol  # noqa: E402
from ddr_rule import dram_net  # noqa: E402

# kicad-cli: KICAD_CLI overrides; else the one on PATH; else the macOS app bundle.
KICAD_CLI = (os.environ.get("KICAD_CLI") or shutil.which("kicad-cli")
             or "/Applications/KiCad/KiCad.app/Contents/MacOS/kicad-cli")

FP_C0402 = "Capacitor_SMD:C_0402_1005Metric"
FP_C0603 = "Capacitor_SMD:C_0603_1608Metric"
FP_C0805 = "Capacitor_SMD:C_0805_2012Metric"
FP_C1210 = "Capacitor_SMD:C_1210_3225Metric"
FP_R0402 = "Resistor_SMD:R_0402_1005Metric"

POWER_NETS = ("+3V3", "GND")

project = kg.Project("hookprobe-sbc", HERE)
rk3588_symbol.register(project)
SOC_REF = "U100"

# Which regulator rail feeds each processor supply group (Radxa Rock 5B v1.45, sheets 10, 14, 18).
SOC_RAIL = {
    "VDD_CPU_BIG0": "VDD_CPU_BIG0_S0", "VDD_CPU_BIG0_MEM": "VDD_CPU_BIG0_S0",
    "VDD_CPU_BIG1": "VDD_CPU_BIG1_S0", "VDD_CPU_BIG1_MEM": "VDD_CPU_BIG1_MEM_S0",
    "VDD_CPU_LIT": "VDD_CPU_LIT_S0", "VDD_CPU_LIT_MEM": "VDD_CPU_LIT_S0",
    "VDD_GPU": "VDD_GPU_S0", "VDD_GPU_MEM": "VDD_GPU_S0",
    "VDD_NPU": "VDD_NPU_S0", "VDD_NPU_MEM": "VDD_NPU_S0",
    "VDD_LOGIC": "VDD_LOG_S0",
    "VDD_VDENC": "VDD_VDENC_S0", "VDD_VDENC_MEM": "VDD_VDENC_S0",
    "PCIE30_AVDD_0V75": "VDD_0V75_S0", "PCIE30_AVDD_1V8": "VCCA_1V8_S0",
    "PCIE20_AVDD_0V85": "VDDA_0V85_S0", "PCIE20_AVDD_1V8": "VCCA_1V8_S0",
    "TYPEC_DP_VDDA_0V85": "VDDA_0V85_S0", "TYPEC_DP_VDD_0V85": "VDDA_0V85_S0", "TYPEC_DP_VDDH_1V8": "VCCA_1V8_S0",
    "USB20_AVDD_1V8": "VCCA_1V8_S0", "USB20_AVDD_3V3": "VCCA_3V3_S0", "USB20_DVDD_0V75": "VDDA_0V75_S0",
}
# Decoupling at the processor for each core rail (same sheet 10), including the MEM pin groups.
SOC_DECOUPLING = [
    ("VDD_GPU_S0", ["22uF"] * 3 + ["10uF"] * 2 + ["4.7uF", "1uF", "100nF", "100nF", "1uF"]),
    ("VDD_LOG_S0", ["22uF"] * 2 + ["10uF"] * 2 + ["4.7uF", "1uF", "100nF", "100nF", "1uF"]),
    ("VDD_VDENC_S0", ["22uF"] * 2 + ["10uF"] * 2 + ["1uF", "100nF", "100nF", "1uF"]),
    ("VDD_NPU_S0", ["22uF"] * 4 + ["10uF", "1uF", "100nF", "1uF", "100nF"]),
    ("VDD_CPU_BIG0_S0", ["100nF", "1uF", "1uF", "4.7uF", "10uF", "10uF"] + ["22uF"] * 3 + ["100nF", "1uF"]),
    ("VDD_CPU_BIG1_S0", ["100nF", "100nF", "1uF", "1uF", "4.7uF", "10uF", "10uF"] + ["22uF"] * 3),
    ("VDD_CPU_BIG1_MEM_S0", ["100nF", "1uF"]),
    ("VDD_CPU_LIT_S0", ["100nF", "4.7uF", "10uF", "10uF"] + ["22uF"] * 3 + ["100nF", "1uF"]),
]

# PCIe3 PHY in its 4 x 1-lane split: (port, lane) -> what the lane feeds.
# Port 0 lane 0 = controller pcie3x4, port 0 lane 1 = pcie2x1l0 (ball names PCIE30X1_0),
# port 1 lane 0 = pcie3x2, port 1 lane 1 = pcie2x1l1 (PCIE30X1_1).
# Derived from the mainline Linux CM3588 NAS device tree (data-lanes = <1 3 2 4>);
# still to be confirmed against Rockchip's PCIe developer guide before layout.
PCIE3_LANES = {("0", "0"): "NVME", ("0", "1"): "ETH1", ("1", "0"): "ACCEL", ("1", "1"): "ETH2"}
# Combo PHYs: 0 = Wi-Fi slot (PCIe, controller pcie2x1l2), 1 = spare, 2 = USB 3 straight to the 5G modem slot.
COMBO_NETS = {"0": "PCIE_WIFI", "1": None, "2": "USB3_MODEM"}
_count = {}


def ref(prefix):
    _count[prefix] = _count.get(prefix, 0) + 1
    return "%s%d" % (prefix, _count[prefix])


def two_pin(sheet, lib_id, prefix, value, x, y, net1, net2, footprint, globals_=()):
    """Place a capacitor or resistor: pin 1 (top) on net1, pin 2 (bottom) on net2."""
    part = sheet.place(lib_id, ref(prefix), value, x, y, footprint)
    for pin, name in (("1", net1), ("2", net2)):
        kind = "power" if name in POWER_NETS else ("global" if name in globals_ else "local")
        sheet.net(part, pin, name, kind=kind)
    return part


class Row:
    """Lays passives out left to right on one line."""

    def __init__(self, sheet, x, y, pitch=7.62):
        self.sheet, self.x, self.y, self.pitch = sheet, x, y, pitch

    def cap(self, value, net1, net2, fp=FP_C0402, globals_=()):
        two_pin(self.sheet, "Device:C", "C", value, self.x, self.y, net1, net2, fp, globals_)
        self.x += self.pitch

    def res(self, value, net1, net2, globals_=()):
        two_pin(self.sheet, "Device:R", "R", value, self.x, self.y, net1, net2, FP_R0402, globals_)
        self.x += self.pitch

    def ind(self, value, net1, net2, globals_=()):
        two_pin(self.sheet, "Device:L", "L", value, self.x, self.y, net1, net2,
                "Inductor_SMD:L_1210_3225Metric", globals_)
        self.x += self.pitch

    def flag(self, net, kind="local"):
        """Mark a rail as driven (it is fed through an inductor or from off this sheet)."""
        self.sheet.flag(net, self.x, self.y, kind)
        self.x += self.pitch

    def gap(self):
        self.x += self.pitch


def glob(sheet, part, mapping, shape="bidirectional"):
    sheet.nets(part, mapping, kind="global", shape=shape)


def pwr(sheet, part, mapping):
    sheet.nets(part, mapping, kind="power")


def pcie_m_key(sheet, x, y, name, tag, row):
    """One PCIe x1 M.2 M-key slot. `tag` names its nets, e.g. NVME -> PCIE_NVME_*."""
    j = sheet.place("Connector:Bus_M.2_Socket_M", ref("J"), name, x, y, vendor_footprint("C590854"), passive=True,
                    fields={"LCSC": "C590854", "Part": "TE 1-2199230-5, M.2 M-key socket, 4.2 mm"})
    p = "PCIE_%s_" % tag
    # Host transmit pair goes through AC-coupling capacitors on this board;
    # the card carries the capacitors for the pair it transmits on.
    sheet.nets(j, {"49": tag + "_TXC_P", "47": tag + "_TXC_N"})
    glob(sheet, j, {"43": p + "RX_P", "41": p + "RX_N"}, "output")
    glob(sheet, j, {"55": p + "REFCLK_P", "53": p + "REFCLK_N", "50": p + "PERST_L"}, "input")
    glob(sheet, j, {"52": p + "CLKREQ_L", "54": "PCIE_WAKE_L"})
    # The two M-key slots have their own 3.3 V converter (up to 3 A per card).
    glob(sheet, j, {"3.3V": "VCC_3V3_M2"}, "input")
    pwr(sheet, j, {"GND": "GND"})
    # Lanes 1-3 unused (one lane per slot), SATA-only and optional pins unused.
    sheet.nc(j, "5", "7", "11", "13", "17", "19", "23", "25", "29", "31", "35", "37",
             "38", "68", "69", "10")
    row.cap("220nF", p + "TX_P", tag + "_TXC_P", globals_=(p + "TX_P",))
    row.cap("220nF", p + "TX_N", tag + "_TXC_N", globals_=(p + "TX_N",))
    row.res("10k", "+3V3", p + "CLKREQ_L", globals_=(p + "CLKREQ_L",))
    row.cap("100nF", "VCC_3V3_M2", "GND", globals_=("VCC_3V3_M2",))
    row.cap("100nF", "VCC_3V3_M2", "GND", globals_=("VCC_3V3_M2",))
    row.cap("22uF", "VCC_3V3_M2", "GND", FP_C0805, globals_=("VCC_3V3_M2",))
    row.cap("22uF", "VCC_3V3_M2", "GND", FP_C0805, globals_=("VCC_3V3_M2",))
    row.gap()
    return j


# ----------------------------------------------------------------- sheet 2 --
def sheet_slots_pcie():
    s = project.sheet("slots_pcie", "M.2 slots: NVMe and accelerator")
    s.text("M.2 M-key slots, one PCIe Gen3 lane each.\\n"
           "J1 NVMe SSD: RK3588 controller pcie3x4, PCIe3 PHY lane 0.\\n"
           "J2 NPU / FPGA card: RK3588 controller pcie3x2, PCIe3 PHY lane 1.\\n"
           "100 MHz reference clocks come from the PCIe clock buffer (sheet not drawn yet).\\n"
           "PCIE_WAKE_L is shared by all PCIe slots (open drain, one pull-up here).", 15, 15)
    row = Row(s, 40.64, 226.06)
    pcie_m_key(s, 101.6, 127.0, "NVMe (M-key)", "NVME", row)
    pcie_m_key(s, 271.78, 127.0, "Accelerator (M-key)", "ACCEL", row)
    row.res("10k", "+3V3", "PCIE_WAKE_L", globals_=("PCIE_WAKE_L",))
    return s


# ----------------------------------------------------------------- sheet 3 --
def sheet_slots_radio():
    s = project.sheet("slots_radio", "M.2 slots: Wi-Fi and 5G modem, SIM")
    s.text("J3 Wi-Fi (E-key): PCIe on RK3588 pcie2x1l2 / combo PHY 0, Bluetooth on USB 2.\\n"
           "J4 5G modem (B-key): USB 3 + USB 2 from the hub, SIM on J5.\\n"
           "VCC_MODEM is a dedicated 3.3 V rail sized for transmit bursts.\\n"
           "MODEM_PWR_EN high switches the modem on (card pulls it low by default).\\n"
           "MODEM_RESET_H high resets the modem (transistor pulls the card's 1.8 V reset pin low).\\n"
           "MODEM_VCC_EN switches the whole VCC_MODEM rail, for a hard power cycle.\\n"
           "SIM detect is not wired in rev A: the holder has no switch, so no SIM hot-swap.", 15, 15)
    row = Row(s, 40.64, 226.06)

    # ---- Wi-Fi, M.2 E-key --------------------------------------------------
    j = s.place("Connector:Bus_M.2_Socket_E", ref("J"), "Wi-Fi (E-key)", 96.52, 127.0, vendor_footprint("C367027"),
                passive=True, fields={"LCSC": "C367027", "Part": "Argosy NASE0-S6701-TSH4, M.2 E-key socket"})
    s.nets(j, {"35": "WIFI_TXC_P", "37": "WIFI_TXC_N"})
    glob(s, j, {"41": "PCIE_WIFI_RX_P", "43": "PCIE_WIFI_RX_N"}, "output")
    glob(s, j, {"47": "PCIE_WIFI_REFCLK_P", "49": "PCIE_WIFI_REFCLK_N", "52": "PCIE_WIFI_PERST_L",
                "56": "WIFI_DISABLE_L", "54": "BT_DISABLE_L", "50": "SUSCLK_32K"}, "input")
    glob(s, j, {"53": "PCIE_WIFI_CLKREQ_L", "55": "PCIE_WAKE_L", "3": "USB2_BT_DP", "5": "USB2_BT_DM"})
    pwr(s, j, {"3.3V": "+3V3", "GND": "GND"})
    s.nc(j, "6", "16",                                    # LEDs
         "9", "11", "13", "15", "17", "19", "21", "23",   # SDIO
         "20", "22", "32", "34", "36",                    # UART
         "8", "10", "12", "14",                           # PCM / I2S
         "38", "40", "42", "44", "46", "48",              # vendor defined, coexistence
         "58", "60", "62", "64",                          # I2C, alert, reserved
         "59", "61", "65", "67", "71", "73", "66", "68", "70")  # second PCIe lane
    row.cap("220nF", "PCIE_WIFI_TX_P", "WIFI_TXC_P", globals_=("PCIE_WIFI_TX_P",))
    row.cap("220nF", "PCIE_WIFI_TX_N", "WIFI_TXC_N", globals_=("PCIE_WIFI_TX_N",))
    row.res("10k", "+3V3", "PCIE_WIFI_CLKREQ_L", globals_=("PCIE_WIFI_CLKREQ_L",))
    row.cap("100nF", "+3V3", "GND")
    row.cap("100nF", "+3V3", "GND")
    row.cap("22uF", "+3V3", "GND", FP_C0805)
    row.cap("22uF", "+3V3", "GND", FP_C0805)
    row.gap()

    # ---- 5G modem, M.2 B-key -----------------------------------------------
    m = s.place("Connector:Bus_M.2_Socket_B", ref("J"), "5G modem (B-key)", 231.14, 127.0, vendor_footprint("C590859"),
                passive=True, fields={"LCSC": "C590859", "Part": "TE 2199230-3, M.2 B-key socket, 4.2 mm"})
    glob(s, m, {"3.3V": "VCC_MODEM"}, "input")
    pwr(s, m, {"GND": "GND"})
    glob(s, m, {"6": "MODEM_PWR_EN", "8": "MODEM_DISABLE_L", "67": "MODEM_RESET_L"}, "input")
    # Reset is a 1.8 V input with its own pull-up on the card: pull it low through a transistor, never drive it high.
    q = s.place("Transistor_FET:2N7002", ref("Q"), "2N7002", 300.99, 180.34, "Package_TO_SOT_SMD:SOT-23")
    glob(s, q, {"G": "MODEM_RESET_H"}, "input")
    glob(s, q, {"D": "MODEM_RESET_L"}, "passive")
    pwr(s, q, {"S": "GND"})
    glob(s, m, {"7": "USB2_MODEM_DP", "9": "USB2_MODEM_DM"})
    # Pins 29/31 carry the pair the modem transmits on (host receive).
    glob(s, m, {"31": "USB3_MODEM_RX_P", "29": "USB3_MODEM_RX_N"}, "output")
    s.nets(m, {"37": "MODEM_TXC_P", "35": "MODEM_TXC_N"})
    s.nets(m, {"36": "UIM_PWR", "30": "UIM_RESET", "32": "UIM_CLK", "34": "UIM_DATA"})
    s.nc(m, "66",                                         # SIM detect, see sheet note
         "1", "21", "69", "75",                           # CONFIG_0..3 (card type straps)
         "10", "25", "38", "68",                          # LED, DPR, DEVSLP, SUSCLK
         "20", "22", "23", "24", "26", "28",              # GPIO 5-11
         "40", "42", "44", "46", "48",                    # GPIO 0-4
         "41", "43", "47", "49", "50", "52", "53", "54", "55",   # PCIe (modem used over USB)
         "59", "61", "63", "65", "60", "62", "64")        # antenna control, coexistence
    row.cap("100nF", "USB3_MODEM_TX_P", "MODEM_TXC_P", globals_=("USB3_MODEM_TX_P",))
    row.cap("100nF", "USB3_MODEM_TX_N", "MODEM_TXC_N", globals_=("USB3_MODEM_TX_N",))
    row.cap("100uF", "VCC_MODEM", "GND", FP_C1210, globals_=("VCC_MODEM",))
    row.cap("100uF", "VCC_MODEM", "GND", FP_C1210, globals_=("VCC_MODEM",))
    row.cap("100nF", "VCC_MODEM", "GND", globals_=("VCC_MODEM",))
    row.cap("33pF", "VCC_MODEM", "GND", globals_=("VCC_MODEM",))
    row.res("100K", "MODEM_RESET_H", "GND", globals_=("MODEM_RESET_H",))
    row.gap()

    # ---- SIM holder and its ESD protection -----------------------------------
    sim = s.place("Connector:SIM_Card", ref("J"), "nano-SIM", 355.6, 96.52,
                  "Connector_Card:nanoSIM_GCT_SIM8060-6-0-14-00", passive=True)
    s.nets(sim, {"VCC": "UIM_PWR", "RST": "UIM_RESET", "CLK": "UIM_CLK", "I/O": "UIM_DATA"})
    pwr(s, sim, {"GND": "GND"})
    s.nc(sim, "VPP")
    esd = s.place("Power_Protection:SRV05-4", ref("U"), "SRV05-4", 355.6, 152.4,
                  "Package_TO_SOT_SMD:SOT-23-6")
    s.nets(esd, {"IO1": "UIM_RESET", "IO2": "UIM_CLK", "IO3": "UIM_DATA", "VP": "UIM_PWR"})
    pwr(s, esd, {"VN": "GND"})
    s.nc(esd, "IO4")
    row.cap("100nF", "UIM_PWR", "GND")
    # The SIM supply comes from the modem card through J4 pin 36, not from this board.
    s.flag("UIM_PWR", 325.12, 76.2)
    return s


# ----------------------------------------------------------------- sheet 4 --
def sheet_soc_pcie():
    s = project.sheet("soc_pcie", "Processor: PCIe and combo PHYs")
    s.text("RK3588 unit 1: PCIe3 PHY (4 lanes, split 4 x 1) and the three combo PHYs.\n"
           "Lane to slot mapping is in PCIE3_LANES in build.py and is still to be confirmed\n"
           "against Rockchip's PCIe guide. Combo PHY 1 is spare (usable for SATA only).\n"
           "RESREF resistors are 200R 1%, as on the Radxa Rock 5B v1.45 schematic (sheet 18).\n"
           "Supply pins go to rails named after the PHY; filtering and decoupling belong on the power sheet.", 15, 15)
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 205.74, 45.72, rk3588_symbol.FOOTPRINT, unit=1)
    row = Row(s, 40.64, 226.06)
    for pin in list(u.pins):
        name, num = pin["name"], pin["number"]
        m = re.match(r"PCIE30_PORT(\d)_(TX|RX)(\d)([PN])$", name)
        if m:
            tag = PCIE3_LANES[(m.group(1), m.group(3))]
            s.net(u, num, "PCIE_%s_%s_%s" % (tag, m.group(2), m.group(4)), kind="global",
                  shape="output" if m.group(2) == "TX" else "input")
            continue
        m = re.match(r"PCIE30_PORT(\d)_REF_CLK([PN])$", name)
        if m:
            s.net(u, num, "PCIE30_PHY%s_REFCLK_%s" % m.groups(), kind="global", shape="input")
            continue
        m = re.match(r"PCIE30_PORT(\d)_RESREF$", name)
        if m:
            net = "PCIE30_P%s_RESREF" % m.group(1)
            s.net(u, num, net, kind="global")
            row.res("200R 1%", net, "GND", globals_=(net,))    # Rock 5B v1.45 sheet 18: R1801, R1807
            continue
        m = re.match(r"(PCIE30|PCIE20)_.*AVDD_?(\dV\d+)$", name)
        if m:
            s.net(u, num, SOC_RAIL["%s_AVDD_%s" % m.groups()], kind="global", shape="input")
            continue
        m = re.match(r"PCIE20_(\d)_(TX|RX|REFCLK)([PN])", name)
        if m:
            use = COMBO_NETS[m.group(1)]
            if use is None or (m.group(2) == "REFCLK" and use != "PCIE_WIFI"):
                s.nc(u, num)
            else:
                s.net(u, num, "%s_%s_%s" % (use, m.group(2), m.group(3)), kind="global",
                      shape="input" if m.group(2) == "RX" else "output")
            continue
        raise SystemExit("soc_pcie: no rule for ball %s (%s)" % (num, name))
    return s


# ----------------------------------------------------------------- sheet 5 --
def sheet_soc_usb():
    s = project.sheet("soc_usb", "Processor: USB and Type-C PHYs")
    s.text("RK3588 unit 2. TYPEC0 feeds USB-C port 1, TYPEC1 feeds USB-C port 2 (USB 3 and DisplayPort share\\n"
           "the same four pairs). USB20_HOST0 is the USB 2 side of the hub; USB20_HOST1 goes to the Wi-Fi\\n"
           "card's Bluetooth. The OTG ID balls are unused (a Type-C port gets its role\\n"
           "from the PD controller); VBUSDET is pulled up on the port sheets. REXT values follow the Radxa Rock 5B v1.45 schematic (sheet 14).", 15, 15)
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 205.74, 45.72, rk3588_symbol.FOOTPRINT, unit=2)
    row = Row(s, 40.64, 226.06)
    host = {"0": "USB2_HUB", "1": "USB2_BT"}
    for pin in list(u.pins):
        name, num = pin["name"], pin["number"]
        m = re.match(r"TYPEC(\d)_SS(RX|TX)(\d)([NP])/", name)
        if m:
            port = int(m.group(1)) + 1
            s.net(u, num, "USBC%d_SS%s%s_%s" % (port, m.group(2), m.group(3), m.group(4)), kind="global")
            continue
        m = re.match(r"TYPEC(\d)_SBU(\d)/", name)
        if m:
            s.net(u, num, "USBC%d_SBU%s" % (int(m.group(1)) + 1, m.group(2)), kind="global")
            continue
        m = re.match(r"TYPEC(\d)_USB20_(?:OTG_)?(DM|DP|ID|VBUSDET)$", name)
        if m:
            if m.group(2) == "ID":      # Type-C ports take their role from the PD controller, not an ID pin
                s.nc(u, num)
                continue
            label = {"DM": "USB2_DM", "DP": "USB2_DP", "VBUSDET": "VBUSDET"}[m.group(2)]
            s.net(u, num, "USBC%d_%s" % (int(m.group(1)) + 1, label), kind="global")
            continue
        m = re.match(r"USB20_HOST(\d)_(DM|DP)$", name)
        if m:
            s.net(u, num, "%s_%s" % (host[m.group(1)], m.group(2)), kind="global")
            continue
        if name.endswith("_REXT"):
            s.net(u, num, name, kind="global")
            # Rock 5B v1.45 sheet 14: DP REXT 8.2K 1% (R1402, R1410); USB 2 REXT 200R 1% (R1400/01/05/06)
            row.res("8.2K 1%" if "_DP" in name else "200R 1%", name, "GND", globals_=(name,))
            continue
        m = re.match(r"TYPEC\d_DP\d_(VDDA_0V85|VDDH_1V8|VDD_0V85)$", name)
        if m:
            s.net(u, num, SOC_RAIL["TYPEC_DP_" + m.group(1)], kind="global", shape="input")
            continue
        if re.match(r"USB20_[AD]VDD_\dV\d+$", name):
            s.net(u, num, SOC_RAIL[name], kind="global", shape="input")
            continue
        raise SystemExit("soc_usb: no rule for ball %s (%s)" % (num, name))
    return s


# ----------------------------------------------------------------- sheet 6 --
def sheet_soc_power():
    s = project.sheet("soc_power", "Processor: core supplies and ground", paper="A2")
    s.text("RK3588 units 11 and 13, with rail assignment and decoupling from the Radxa Rock 5B v1.45 schematic,\\n"
           "sheet 10. The MEM pin groups share their core rail, except CPU_BIG1_MEM which has its own rail.\\n"
           "Net ties join each remotely sensed rail to its _FB sense net; place them at the processor balls.\\n"
           "All 421 ground balls are stacked on the single VSS pin of the ground unit.", 15, 15)
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 152.4, 45.72, rk3588_symbol.FOOTPRINT, unit=11)
    for pin in list(u.pins):
        s.net(u, pin["number"], SOC_RAIL[re.sub(r"_\d+$", "", pin["name"])], kind="global", shape="input")
    g = s.place("soc:RK3588", SOC_REF, "RK3588", 304.8, 60.96, rk3588_symbol.FOOTPRINT, unit=13)
    pwr(s, g, {"VSS": "GND"})
    rows = [Row(s, 25.4, 289.56), Row(s, 25.4, 350.52)]
    for i, (rail, values) in enumerate(SOC_DECOUPLING):
        row = rows[0] if i < 4 else rows[1]
        for value in values:
            fp = FP_C0603 if value == "22uF" else FP_C0402
            row.cap(value, rail, "GND", fp, globals_=(rail,))
        row.gap()
    x = 406.4
    for rail in ("VDD_GPU_S0", "VDD_CPU_LIT_S0", "VDD_LOG_S0", "VDD_VDENC_S0",
                 "VDD_CPU_BIG0_S0", "VDD_CPU_BIG1_S0", "VDD_NPU_S0"):
        tie = s.place("Device:NetTie_2", ref("NT"), "sense tie", x, 76.2, "NetTie:NetTie-2_SMD_Pad0.5mm")
        glob(s, tie, {"1": rail, "2": rail + "_FB"}, "passive")
        x += 25.4
    return s


# ------------------------------------------------------------ vendor parts --
_vendor = {}


def vendor_footprint(lcsc_id):
    """Register a footprint fetched from LCSC's library (no symbol); returns its footprint name."""
    d = os.path.join(HERE, "..", "vendor", "lcsc_" + lcsc_id, "part.pretty")
    fp = [f for f in os.listdir(d) if f.endswith(".kicad_mod")][0]
    project.add_footprint(os.path.join(d, fp))
    return "%s:%s" % (kg.LIB, fp[:-len(".kicad_mod")])


def vendor_part(lcsc_id, power=r"VDD|VIN|GND", types=()):
    """Register a part fetched from LCSC's library; returns (lib_id, footprint).

    `types` is a list of (regex, electrical type) tried in order on each pin name;
    pins matching `power` become power inputs and everything else is passive.
    """
    if lcsc_id not in _vendor:
        d = os.path.join(HERE, "..", "vendor", "lcsc_" + lcsc_id)
        with open(os.path.join(d, "part.native.kicad_sym"), encoding="utf-8") as fh:
            sym = kg.find_all(kg.parse(fh.read()), "symbol")[0]
        old = str(sym[1])
        clean = re.sub(r"\{slash\}|/|\s", "_", old)    # '/' and spaces are awkward in a KiCad symbol name
        if clean != old:
            sym[1] = kg.Q(clean)
            for sub in kg.find_all(sym, "symbol"):
                sub[1] = kg.Q(clean + str(sub[1])[len(old):])
        for sub in kg.find_all(sym, "symbol"):
            for p in kg.find_all(sub, "pin"):
                pin_name = str(kg.find(p, "name")[1])
                for pattern, kind in types:
                    if re.search(pattern, pin_name):
                        p[1] = kind
                        break
                else:
                    p[1] = "power_in" if re.search(power, pin_name) else "passive"
        project.add_symbol(sym)
        fp = [f for f in os.listdir(os.path.join(d, "part.pretty")) if f.endswith(".kicad_mod")][0]
        project.add_footprint(os.path.join(d, "part.pretty", fp))
        _vendor[lcsc_id] = ("vendor:" + str(sym[1]), "%s:%s" % (kg.LIB, fp[:-len(".kicad_mod")]))
    return _vendor[lcsc_id]


# ------------------------------------------------------------ sheets 7, 8 --
def sheet_ethernet(n):
    """One 2.5GbE port: RTL8125BG on a PCIe lane, copied from Radxa Rock 5B v1.45 sheet 24."""
    e = "ETH%d_" % n
    core = e + "VDD09"
    s = project.sheet("eth%d" % n, "2.5GbE port %d: RTL8125BG" % n)
    s.text("Copied from the Radxa Rock 5B v1.45 schematic, sheet 24 (RTL8125BG, external 0.95 V core supply).\\n"
           "Left out on purpose: the zero-ohm option links, the unpopulated strap resistors, and the\\n"
           "common-mode/ESD filters on the MDI pairs (the reference part could not be matched to an LCSC part).\\n"
           "Jack: HanRun HR911130C, pinout taken from its datasheet (vendor/lcsc_C50933/datasheet.pdf), which\\n"
           "matches the LCSC symbol and not the Radxa drawing. It is rated 100/1000Base-T only: validate it at\\n"
           "2.5 Gb or substitute a 2.5G-rated jack. Centre tap P1 has a capacitor to ground only, as in the reference.\\n"
           "Reference clock comes from the PCIe clock buffer (sheet not drawn yet).", 15, 15)
    chip_id, chip_fp = vendor_part("C3013605")
    u = s.place(chip_id, ref("U"), "RTL8125BG-CG", 139.7, 121.92, chip_fp, fields={"LCSC": "C3013605"})
    pwr(s, u, {"19": "+3V3", "33": "+3V3", "29": "+3V3", "46": "+3V3", "43": "+3V3", "34": "+3V3",
               "40": "GND", "49": "GND"})
    s.nets(u, {"15": e + "AVDD33_PLL"})
    s.nets(u, {p: core for p in ("8", "28", "47", "11", "16", "22", "37")})
    s.nets(u, {"12": e + "RSET", "9": e + "XTAL2", "10": e + "XTAL1", "1": e + "ISOLATEB",
               "2": e + "LANWAKEB", "3": e + "GPI", "6": e + "POW_EXT_SWR",
               "30": e + "LED0", "27": e + "LED1", "25": e + "LED2",
               "41": e + "HSIP", "42": e + "HSIN", "38": e + "HSOP", "39": e + "HSON"})
    glob(s, u, {"36": "PCIE_%sPERST_L" % e, "44": "PCIE_%sREFCLK_P" % e, "45": "PCIE_%sREFCLK_N" % e}, "input")
    glob(s, u, {"48": "PCIE_%sCLKREQ_L" % e})
    for i, (p, m) in enumerate((("13", "14"), ("17", "18"), ("20", "21"), ("23", "24"))):
        glob(s, u, {p: "%sMDI%d_P" % (e, i), m: "%sMDI%d_N" % (e, i)})
    s.nc(u, "4", "5", "7",        # not connected on the BG variant
         "26", "31", "32", "35")  # SPICSB, EECS/SCL, EEPROM_SEL (straps unpopulated in the reference), LED3

    # 0.95 V core supply (reference U15, L27, R300/R303, C509-C511)
    reg_id, reg_fp = vendor_part("C517210")
    r = s.place(reg_id, ref("U"), "LP3218AB5F", 320.04, 76.2, reg_fp, fields={"LCSC": "C517210"})
    pwr(s, r, {"VIN": "+3V3", "GND": "GND"})
    s.nets(r, {"EN": e + "CORE_EN", "LX": e + "CORE_LX", "FB": e + "CORE_FB"})
    ind = s.place("Device:L", ref("L"), "1uH", 363.22, 76.2, "Inductor_SMD:L_0805_2012Metric")
    s.nets(ind, {"1": e + "CORE_LX", "2": core})
    s.flag(core, 381.0, 60.96)                 # regulated rail, fed through the inductor
    bead = s.place("Device:FerriteBead", ref("FB"), "120R@100MHz 1.3A", 279.4, 127.0,
                   "Inductor_SMD:L_0402_1005Metric", fields={"Part": "UPZ1005D121-1R3TF"})
    pwr(s, bead, {"1": "+3V3"})
    s.nets(bead, {"2": e + "AVDD33_PLL"})
    s.flag(e + "AVDD33_PLL", 294.64, 111.76)   # fed through the ferrite bead
    # Network jack with magnetics. Pin functions from the HanRun datasheet schematic:
    # P1 common centre tap, P2/P3 pair 0, P4/P7 pair 1, P5/P6 pair 2, P8/P9 pair 3, P10 chassis,
    # 11 (anode) / 12 green LED, 14 (anode) / 13 yellow LED.
    jack_id, jack_fp = vendor_part("C50933")
    j = s.place(jack_id, ref("J"), "HR911130C", 345.44, 175.26, jack_fp, fields={"LCSC": "C50933"})
    glob(s, j, {"P2": e + "MDI0_P", "P3": e + "MDI0_N", "P4": e + "MDI1_P", "P7": e + "MDI1_N",
                "P5": e + "MDI2_P", "P6": e + "MDI2_N", "P8": e + "MDI3_P", "P9": e + "MDI3_N"})
    glob(s, j, {"11": e + "JACK_GP", "12": e + "JACK_GN", "14": e + "JACK_YP", "13": e + "JACK_YN"})
    s.nets(j, {"P1": e + "JACK_CT"})
    glob(s, j, {"P10": "GND_CHASSIS", "SHIELD0": "GND_CHASSIS", "SHIELD1": "GND_CHASSIS"}, "passive")
    xtal = s.place("Device:Crystal_GND24", ref("Y"), "25MHz 12pF", 248.92, 55.88,
                   "Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm")
    s.nets(xtal, {"1": e + "XTAL1", "3": e + "XTAL2"})
    pwr(s, xtal, {"2": "GND", "4": "GND"})

    a = Row(s, 25.4, 226.06)       # resistors and small-signal parts
    a.res("2.49K 1%", e + "RSET", "GND")
    a.res("1K", "+3V3", e + "ISOLATEB")
    a.res("15K 1%", e + "ISOLATEB", "GND")
    a.res("4.7K", "+3V3", e + "LANWAKEB")
    a.res("4.7K", "+3V3", e + "GPI")
    a.res("4.7K", "+3V3", e + "POW_EXT_SWR")
    a.res("4.7K", "+3V3", e + "LED1")
    a.res("4.7K", "+3V3", "PCIE_%sCLKREQ_L" % e, globals_=("PCIE_%sCLKREQ_L" % e,))
    a.gap()
    for led, jack, value in (("LED0", "JACK_GP", "249R 1%"), ("LED1", "JACK_GN", "249R 1%"), ("LED2", "JACK_YN", "0R")):
        a.res(value, e + led, e + jack, globals_=(e + jack,))
    a.res("510R", "+3V3", e + "JACK_YP", globals_=(e + "JACK_YP",))
    a.gap()
    a.cap("27pF", e + "XTAL1", "GND")
    a.cap("27pF", e + "XTAL2", "GND")
    a.cap("100nF", e + "JACK_CT", "GND")                          # reference C534
    for _ in range(2):                                            # chassis to ground, reference C537-C540
        a.cap("100nF", "GND_CHASSIS", "GND", globals_=("GND_CHASSIS",))
    a.gap()
    for chip_pin, soc in (("HSIP", "TX_P"), ("HSIN", "TX_N"), ("HSOP", "RX_P"), ("HSON", "RX_N")):
        g = "PCIE_%s%s" % (e, soc)
        a.cap("100nF", g, e + chip_pin, globals_=(g,))
    a.gap()
    a.res("4.7K", "+3V3", e + "CORE_EN")
    a.res("100K", e + "CORE_EN", "GND")
    a.res("69.8K 1%", core, e + "CORE_FB")     # reference prints 69K; nearest standard value, gives 0.949 V
    a.cap("22pF", core, e + "CORE_FB")
    a.res("120K 1%", e + "CORE_FB", "GND")

    b = Row(s, 25.4, 266.7)        # decoupling, grouped as in the reference
    b.cap("10uF", "+3V3", "GND", FP_C0805)
    b.cap("4.7uF", "+3V3", "GND", FP_C0805)
    for value in ["100nF"] * 5 + ["2.2uF"] * 4 + ["1uF"]:
        b.cap(value, "+3V3", "GND")
    b.gap()
    b.cap("10uF", e + "AVDD33_PLL", "GND", FP_C0805)
    b.cap("100nF", e + "AVDD33_PLL", "GND")
    b.gap()
    b.cap("22uF", core, "GND", FP_C0805)
    b.cap("10uF", core, "GND", FP_C0805)
    b.cap("10uF", core, "GND", FP_C0805)
    for value in ["2.2uF"] * 4 + ["100nF"] * 3:
        b.cap(value, core, "GND")
    return s


# ----------------------------------------------------------------- sheet 9 --
# RK806-1 switching rails, from Radxa Rock 5B v1.45 sheet 22.
# (buck, rail, inductor, input cap, output caps, remote sense from the processor, feedback divider)
PMIC_BUCKS = [
    (1, "VDD_GPU_S0", "0.22uH", "22uF", ["1uF", "47uF", "47uF", "22uF", "22uF"], True, None),
    (2, "VDD_CPU_LIT_S0", "0.22uH", "22uF", ["1uF", "22uF", "22uF", "22uF", "22uF"], True, None),
    (3, "VDD_LOG_S0", "0.22uH", "22uF", ["1uF", "22uF", "22uF", "22uF", "22uF"], True, None),
    (4, "VDD_VDENC_S0", "0.22uH", "22uF", ["1uF", "22uF", "22uF", "22uF", "22uF"], True, None),
    (5, "VDD_DDR_S0", "0.47uH", "10uF", ["22uF", "22uF", "10uF", "1uF"], True, None),
    (6, "VDD2_DDR_S3", "0.47uH", "10uF", ["22uF", "22uF", "10uF"], False, ("120K 1%", "100K 1%")),   # 1.1 V, LPDDR4/4X
    (7, "VCC_2V0_PLDO_S3", "0.47uH", "10uF", ["22uF", "22uF"], False, None),
    (8, "VCC_3V3_S3", "0.47uH", "10uF", ["22uF", "22uF"], False, None),
    (9, "VDDQ_DDR_S0", "0.47uH", "10uF", ["22uF", "22uF", "10uF"], False, ("20K 1%", "100K 1%")),    # 0.6 V, LPDDR4/4X
    (10, "VCC_1V8_S3", "0.47uH", "10uF", ["22uF", "22uF"], False, None),
]
PMIC_VOUT_PIN = {1: "49", 2: "37", 3: "56", 4: "24", 5: "46", 6: "30", 7: "41", 8: "5", 9: "67", 10: "25"}
# (LDO supply pin, its source rail, [(output pin, rail)], output capacitor)
PMIC_LDOS = [
    ("VCC11", "VCC_2V0_PLDO_S3", [("PLDO1", "VCCA_1V8_S0"), ("PLDO2", "VCC_1V8_S0"), ("PLDO3", "VDDA_1V2_S0")], "1uF"),
    ("VCC12", "VCC4V0_SYS", [("PLDO4", "VCCA_3V3_S0"), ("PLDO5", "VCCIO_SD_S0")], "1uF"),
    ("VCC13", "VCC_1V1_NLDO_S3", [("NLDO1", "VDD_0V75_S3"), ("NLDO2", "VDDA_DDR_PLL_S0"), ("NLDO3", "VDDA_0V75_S0")], "2.2uF"),
    ("VCC14", "VCC_1V1_NLDO_S3", [("NLDO4", "VDDA_0V85_S0"), ("NLDO5", "VDD_0V75_S0")], "2.2uF"),
]


def sheet_pmic():
    s = project.sheet("pmic", "Power chip: RK806-1", paper="A2")
    s.text("Copied from the Radxa Rock 5B v1.45 schematic, sheet 22. Rail names are the reference's.\\n"
           "VCC4V0_SYS (4.0 V system rail) and VCC_1V1_NLDO_S3 come from regulators that are not drawn yet.\\n"
           "Bucks 1-5 are sensed at the processor: each VOUT pin goes to a <rail>_FB net with 100R to the local\\n"
           "output; the sense net must be tied to the rail at the processor balls (net tie, not drawn yet).\\n"
           "Buck 6 and 9 dividers are the LPDDR4/4X values (1.1 V and 0.6 V); LPDDR5 needs 110K and a 0R/open pair.\\n"
           "J (3-pin header): short pin 1 to 2 for the power button, pin 3 to 2 for reset.", 15, 15)
    chip_id, chip_fp = vendor_part("C5156483", power=r"^VCC\d+$|^VCCA$|^PAD$",
                                   types=[(r"^[PN]LDO\d$|^VCCIO$", "power_out")])
    u = s.place(chip_id, ref("U"), "RK806-1", 297.18, 152.4, chip_fp, fields={"LCSC": "C5156483"})

    def G(*nets):
        return tuple(n for n in nets if n not in POWER_NETS and not n.startswith(("PMIC_SW", "PMIC_FB", "PMIC_VDC")))

    a = Row(s, 25.4, 325.12)
    b = Row(s, 25.4, 381.0)

    def cap(row, value, net, other="GND"):
        fp = FP_C0805 if value == "47uF" else (FP_C0603 if value in ("10uF", "22uF") else FP_C0402)
        row.cap(value, net, other, fp, globals_=G(net, other))

    def res(row, value, net, other):
        row.res(value, net, other, globals_=G(net, other))

    for n, rail, coil, cin, couts, sensed, divider in PMIC_BUCKS:
        sw = "PMIC_SW%d" % n
        glob(s, u, {"VCC%d" % n: "VCC4V0_SYS"}, "input")
        s.nets(u, {"SW%d" % n: sw})
        row = a if n <= 5 else b
        row.cap(cin, "VCC4V0_SYS", "GND", FP_C0805 if cin == "22uF" else FP_C0603, globals_=("VCC4V0_SYS",))
        row.ind(coil, sw, rail, globals_=(rail,))
        for value in couts:
            cap(row, value, rail)
        if sensed:
            glob(s, u, {PMIC_VOUT_PIN[n]: rail + "_FB"}, "input")
            res(row, "100R", rail, rail + "_FB")
        else:
            glob(s, u, {PMIC_VOUT_PIN[n]: rail}, "input")
        if divider:
            fb = "PMIC_FB%d" % n
            s.nets(u, {"FB%d" % n: fb})
            res(row, divider[0], rail, fb)
            cap(row, "100pF", rail, fb)
            res(row, divider[1], fb, "GND")
        row.flag(rail, "global")
        row.gap()
    s.nc(u, "FB1", "FB2", "FB5", "SYNC", "SYNC_CLK")

    c = Row(s, 330.2, 381.0)
    for supply, source, outputs, cout in PMIC_LDOS:
        glob(s, u, {supply: source}, "input")
        cap(c, "1uF", source)
        for pin, rail in outputs:
            glob(s, u, {pin: rail}, "output")
            cap(c, cout, rail)
        c.gap()

    # management section
    glob(s, u, {"VCCA": "VCC4V0_SYS"}, "input")
    glob(s, u, {"VCCIO": "VCC_1V8_S3_PLDO6"}, "output")          # internal PLDO6 output
    glob(s, u, {"CS": "PMIC_SPI_CS", "MOSI/SDA": "PMIC_SPI_MOSI", "CLK/SCL": "PMIC_SPI_CLK",
                "MISO/PWRCRTL3": "PMIC_PWR_CTRL3", "PWRCRTL2": "PMIC_PWR_CTRL2", "PWRCRTL1": "PMIC_PWR_CTRL1",
                "EXT_EN": "PMIC_EXT_EN_OUT", "INT": "PMIC_INT_L", "RESETB": "RESET_L", "PWRON": "PWRON_L"})
    s.nets(u, {"VDC": "PMIC_VDC"})
    pwr(s, u, {"PAD": "GND"})
    m = Row(s, 462.28, 325.12)
    cap(m, "1uF", "VCC4V0_SYS")
    cap(m, "4.7uF", "VCC4V0_SYS")
    cap(m, "1uF", "VCC_1V8_S3_PLDO6")
    res(m, "200K", "VCC4V0_SYS", "PMIC_VDC")
    res(m, "200K", "PMIC_VDC", "GND")
    cap(m, "1nF", "PMIC_VDC")
    cap(m, "1nF", "PWRON_L")
    res(m, "100K", "PMIC_SPI_CS", "GND")
    res(m, "100K", "PMIC_SPI_MOSI", "GND")
    res(m, "10K", "VCC_1V8_S3", "PMIC_INT_L")
    res(m, "10K", "VCC_1V8_S3", "RESET_L")
    cap(m, "10nF", "RESET_L")
    m.gap()
    btn = s.place("Connector_Generic:Conn_01x03", ref("J"), "Power / reset buttons", 520.7, 248.92,
                  "Connector_PinHeader_2.54mm:PinHeader_1x03_P2.54mm_Vertical", passive=True)
    glob(s, btn, {"1": "PWRON_L", "3": "RESET_L"})
    pwr(s, btn, {"2": "GND"})
    # protection on the 4 V rail: reverse clamp and the TVS the reference says must not be removed
    d1 = s.place("Device:D_Schottky", ref("D"), "B5819WS", m.x, m.y, "Diode_SMD:D_SOD-323")
    glob(s, d1, {"K": "VCC4V0_SYS"}, "passive")
    pwr(s, d1, {"A": "GND"})
    d2 = s.place("Device:D_TVS", ref("D"), "AZ5825-01F", m.x + 25.4, m.y, "Diode_SMD:D_0402_1005Metric")
    glob(s, d2, {"A1": "VCC4V0_SYS"}, "passive")
    pwr(s, d2, {"A2": "GND"})
    return s


# ---------------------------------------------------------------- sheet 10 --
def sheet_core_regs():
    """Big-core and NPU regulators and the 1.1 V rail, from Radxa Rock 5B v1.45 sheet 23."""
    s = project.sheet("core_regs", "Core regulators: big cores, NPU, 1.1 V")
    s.text("Copied from the Radxa Rock 5B v1.45 schematic, sheet 23.\\n"
           "U (RK860-2) big core 0 and U (RK860-3) big core 1 share I2C0; the NPU regulator (RK860-2) is on I2C1.\\n"
           "Each VOUT pin is the remote sense input: it goes to <rail>_FB, tied to the rail at the processor.\\n"
           "VCC_3V3_S0 switch: SY6280AAC in place of the reference's SGM2576/TT9107 (same pinout and current-limit\\n"
           "formula, 6800 / R in amps; 4.7K gives 1.45 A). The reference's LCD supply is not needed.", 15, 15)
    a = Row(s, 25.4, 205.74)
    b = Row(s, 25.4, 256.54)
    regs = [("C5156489", "RK860-2", "VDD_CPU_BIG0_S0", "CPU_BIG0_VSEL", "I2C0", ["1uF"] + ["22uF"] * 5),
            ("C5156487", "RK860-3", "VDD_CPU_BIG1_S0", "CPU_BIG1_VSEL", "I2C0", ["1uF"] + ["22uF"] * 5),
            ("C5156489", "RK860-2", "VDD_NPU_S0", "NPU_VSEL", "I2C1", ["1uF", "47uF", "47uF", "22uF", "22uF", "22uF"])]
    for i, (lcsc, value, rail, vsel, bus, couts) in enumerate(regs):
        part_id, fp = vendor_part(lcsc)
        u = s.place(part_id, ref("U"), value, 76.2 + i * 124.46, 91.44, fp, fields={"LCSC": lcsc})
        sw = "SW_" + rail
        glob(s, u, {"VIN": "VCC4V0_SYS"}, "input")
        pwr(s, u, {"GND": "GND", "AGND": "GND"})
        s.nets(u, {"LX": sw, "EN": "BIG_NPU_EN"})
        glob(s, u, {"VOUT": rail + "_FB"}, "input")
        glob(s, u, {"VSEL": vsel, "SDA": bus + "_SDA_M2", "SCL": bus + "_SCL_M2"})
        row = a if i < 2 else b
        row.cap("22uF", "VCC4V0_SYS", "GND", FP_C0805, globals_=("VCC4V0_SYS",))
        row.cap("22uF", "VCC4V0_SYS", "GND", FP_C0805, globals_=("VCC4V0_SYS",))
        row.ind("0.22uH", sw, rail, globals_=(rail,))
        row.res("100R", rail, rail + "_FB", globals_=(rail, rail + "_FB"))
        for c in couts:
            row.cap(c, rail, "GND", FP_C0805 if c == "47uF" else (FP_C0603 if c == "22uF" else FP_C0402),
                    globals_=(rail,))
        row.flag(rail, "global")
        row.gap()
    # enable for all three: divider from the always-on 3.3 V rail (reference R2302, R2303)
    b.res("100K", "VCC_3V3_S3", "BIG_NPU_EN", globals_=("VCC_3V3_S3",))
    b.res("120K", "BIG_NPU_EN", "GND")
    b.gap()
    # big core 1 memory supply: its core rail through a ferrite bead (reference FB2300, C2316)
    bead = s.place("Device:FerriteBead", ref("FB"), "120R@100MHz", b.x, b.y, "Inductor_SMD:L_0603_1608Metric")
    glob(s, bead, {"1": "VDD_CPU_BIG1_S0", "2": "VDD_CPU_BIG1_MEM_S0"}, "passive")
    b.x += b.pitch
    b.cap("22uF", "VDD_CPU_BIG1_MEM_S0", "GND", FP_C0603, globals_=("VDD_CPU_BIG1_MEM_S0",))
    b.flag("VDD_CPU_BIG1_MEM_S0", "global")
    b.gap()
    # 1.1 V rail feeding the power chip's low-voltage linear regulators (reference U2302)
    part_id, fp = vendor_part("C78988", power=r"^IN$|GND")
    r = s.place(part_id, ref("U"), "SY8089AAAC", 200.66, 152.4, fp, fields={"LCSC": "C78988"})
    glob(s, r, {"IN": "VCC4V0_SYS"}, "input")
    pwr(s, r, {"GND": "GND"})
    s.nets(r, {"EN": "V1V1_EN", "LX": "V1V1_LX", "FB": "V1V1_FB"})
    rail = "VCC_1V1_NLDO_S3"
    b.cap("10uF", "VCC4V0_SYS", "GND", FP_C0603, globals_=("VCC4V0_SYS",))
    b.res("10K", "PMIC_EXT_EN_OUT", "V1V1_EN", globals_=("PMIC_EXT_EN_OUT",))
    b.ind("2.2uH", "V1V1_LX", rail, globals_=(rail,))
    b.res("100K 1%", rail, "V1V1_FB", globals_=(rail,))
    b.cap("100pF", rail, "V1V1_FB", globals_=(rail,))
    b.res("120K 1%", "V1V1_FB", "GND")
    b.cap("22uF", rail, "GND", FP_C0603, globals_=(rail,))
    b.cap("100nF", rail, "GND", globals_=(rail,))
    b.flag(rail, "global")
    b.gap()
    # switched 3.3 V rail for the processor's 3.3 V IO banks (reference U2305, R2311, R2322, C2330, C2332)
    part_id, fp = vendor_part("C55136", power=r"^IN$|GND", types=[(r"^OUT$", "power_out")])
    sw = s.place(part_id, ref("U"), "SY6280AAC", 320.04, 152.4, fp, fields={"LCSC": "C55136"})
    glob(s, sw, {"IN": "VCC_3V3_S3"}, "input")
    glob(s, sw, {"OUT": "VCC_3V3_S0"}, "output")
    pwr(s, sw, {"GND": "GND"})
    s.nets(sw, {"EN": "V3V3S0_EN", "ISET": "V3V3S0_ISET"})
    b.cap("10uF", "VCC_3V3_S3", "GND", FP_C0603, globals_=("VCC_3V3_S3",))
    # SY6280 EN needs 2.0 V (its datasheet); the reference's 1.8 V enable suited its SGM2576, not this part.
    b.res("10K", "VCCA_3V3_S0", "V3V3S0_EN", globals_=("VCCA_3V3_S0",))
    b.res("100K", "V3V3S0_EN", "GND")
    b.res("4.7K", "V3V3S0_ISET", "GND")
    b.cap("10uF", "VCC_3V3_S0", "GND", FP_C0603, globals_=("VCC_3V3_S0",))
    return s


# ---------------------------------------------------------------- sheet 11 --
# Input converters: five MP8759 (26 V, 8 A), each wired like the 5 V stage on Radxa Rock 5B v1.45 sheet 20.
# (rail, feedback top, feedback bottom, what it feeds). Output = 0.6 V x (1 + top / bottom).
# Last field: what switches the converter on. None = whenever VIN is present; otherwise a logic net.
INPUT_BUCKS = [
    ("VCC5V0_SYS", "47K 1%", "6.34K 1%", "5.05 V: USB ports (5.25 V is the limit with tolerances). On whenever VIN is present", None),
    ("VCC4V0_SYS", "47K 1%", "8.2K 1%", "4.04 V: power chip and core regulators. On whenever VIN is present", None),
    ("+3V3", "47K 1%", "10.2K 1%", "3.36 V: Wi-Fi, Ethernet, logic. Follows VCC_3V3_S0", "VCC_3V3_S0"),
    ("VCC_3V3_M2", "47K 1%", "10.2K 1%", "3.36 V: NVMe and accelerator slots. Follows VCC_3V3_S0", "VCC_3V3_S0"),
    ("VCC_MODEM", "47K 1%", "10.2K 1%", "3.36 V: 5G modem. Switched by software (MODEM_VCC_EN)", "MODEM_VCC_EN"),
]


def sheet_power_input():
    s = project.sheet("power_input", "Input converters: 5 V, 4 V and three 3.3 V rails", paper="A2")
    s.text("Five MP8759 converters, each copied from the 5 V stage of the Radxa Rock 5B v1.45 schematic, sheet 20.\n"
           "Differences from the reference, to be checked against the MP8759 datasheet before layout:\n"
           "  - all five run directly from VIN (the reference feeds its 4 V stage from the 5 V rail);\n"
           "  - the three 3.3 V rails are new, with a 47K / 10.2K divider (0.6 V reference gives 3.36 V);\n"
           "  - every stage uses 1.5 uH, the datasheet's table value for 3.3 V and 5 V outputs;\n"
           "  - ENABLE: the pin's absolute maximum is 4.5 V. The 5 V and 4 V stages start with VIN through a\n"
           "    100K / 75K divider clamped by a 3.6 V zener. The three 3.3 V stages are switched by logic:\n"
           "    +3V3 and VCC_3V3_M2 follow VCC_3V3_S0, so nothing feeds the processor's pins before its own\n"
           "    supplies are up; VCC_MODEM is switched by software so a hung modem can be power-cycled.\n"
           "26 V is the MP8759's ABSOLUTE MAXIMUM input, not a working limit: power the board from 20 V or less\\n"
           "(USB-C PD up to 20 V, or a 12 V to 19 V DC supply). The power entry sheet feeds VIN.", 15, 15)
    part_id, fp = vendor_part("C3187827", power=r"^VIN$|GND")
    rows = [Row(s, 25.4, 264.16), Row(s, 25.4, 325.12)]
    for i, (rail, top, bottom, note, enable) in enumerate(INPUT_BUCKS):
        t = "IN%d_" % (i + 1)
        u = s.place(part_id, ref("U"), "MP8759GD-Z", 76.2 + i * 104.14, 119.38, fp, fields={"LCSC": "C3187827"})
        s.text(note, 40.64 + i * 104.14, 76.2, size=1.27)
        glob(s, u, {"VIN": "VIN"}, "input")
        pwr(s, u, {"PGND": "GND", "AGND": "GND"})
        s.nets(u, {"EN": t + "EN", "BST": t + "BST", "SW": t + "SW", "FB": t + "FB", "VCC": t + "VCC",
                   "PG": t + "PG", "MODE": t + "MODE"})
        s.nc(u, "NC")
        row = rows[0] if i < 3 else rows[1]
        power = rail in POWER_NETS
        g = () if power else (rail,)
        if power:
            pwr(s, u, {"VOUT": rail})
        else:
            glob(s, u, {"VOUT": rail}, "output")
        row.cap("10uF 25V", "VIN", "GND", "Capacitor_SMD:C_1206_3216Metric", globals_=("VIN",))
        row.cap("10uF 25V", "VIN", "GND", "Capacitor_SMD:C_1206_3216Metric", globals_=("VIN",))
        row.cap("100nF 50V", "VIN", "GND", FP_C0603, globals_=("VIN",))
        if enable is None:
            # EN is rated 4.5 V absolute maximum (MP8759 datasheet): divide VIN and clamp with a zener.
            # 100K / 75K starts the converter from 3.2 V (the chip's own 4.5 V lockout then decides);
            # the zener holds EN near 3.6 V at any input up to 24 V.
            row.res("100K", "VIN", t + "EN", globals_=("VIN",))
            row.res("75K", t + "EN", "GND")
            z = s.place("Device:D_Zener", ref("D"), "BZT52C3V6S", row.x, row.y, "Diode_SMD:D_SOD-323")
            s.net(z, "K", t + "EN")
            pwr(s, z, {"A": "GND"})
            row.x += row.pitch * 2
        else:
            row.res("10K", enable, t + "EN", globals_=(enable,))
            row.res("100K", t + "EN", "GND")
        row.res("3.3R", t + "BST", t + "BSTC")
        row.cap("220nF", t + "BSTC", t + "SW")
        row.ind("1.5uH 10A", t + "SW", rail, globals_=g)
        row.res(top, rail, t + "FB", globals_=g)
        row.res(bottom, t + "FB", "GND")
        row.cap("1uF", t + "VCC", "GND")
        row.res("100K", t + "VCC", t + "PG")
        row.res("100K", t + "VCC", t + "MODE")
        for value in ["22uF"] * 4 + ["100nF", "100nF"]:
            row.cap(value, rail, "GND", FP_C0805 if value == "22uF" else FP_C0402, globals_=g)
        row.flag(rail, "power" if power else "global")
        row.gap()
    rows[1].flag("GND", "power")       # ground reference enters the board at the input connectors
    return s


# ------------------------------------------------------------ sheets 12, 13 --
def ddr_net(reference_name):
    """Our net name for a reference memory net: the same, without the 'LP4/4X_' part ('/' is awkward in KiCad)."""
    return reference_name.replace("LP4/4X_", "")


def sheet_ddr(channel):
    """One memory channel: RK3588 DDR unit plus its LPDDR4X chip (Radxa Rock 5B v1.45 sheets 4 and 12)."""
    halves = "AB" if channel == 0 else "CD"
    ch = "DDR_CH%d_" % channel
    s = project.sheet("ddr%d" % channel, "Memory channel %d: LPDDR4X" % channel, paper="A2")
    s.text("Copied from the Radxa Rock 5B v1.45 schematic, sheets 4 and 12. Net names follow the reference, minus 'LP4/4X_'.\\n"
           "tools/verify_ddr.py confirms every memory-chip signal ball and its net against the reference page.\\n"
           "LPDDR4X only: VDDQ is tied to the 0.6 V rail, and VDD1 is taken straight from VCC_1V8_S3 (the reference\\n"
           "has zero-ohm option links there). The LPDDR5-only pins (WCK, A6) are left unconnected, as in the reference.\\n"
           "This interface must be laid out by copying Rockchip's memory layout template, not routed freehand.", 15, 15)
    a = Row(s, 25.4, 340.36)
    b = Row(s, 25.4, 393.7)

    def g(*nets):
        return tuple(n for n in nets if n not in POWER_NETS and not n.startswith(("ZQ_", "ODT_")))

    # ---- processor side ------------------------------------------------------
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 139.7, 40.64, rk3588_symbol.FOOTPRINT, unit=3 + channel)
    for pin in list(u.pins):
        name, num = pin["name"], pin["number"]
        tail = name[len(ch):]
        if re.match(r"(DQ\d+|DM\d|DQS\d[PN]|A[0-5]|LP4/4X_CS\d)_[A-D]$", tail):
            s.net(u, num, ddr_net(name), kind="global")
        elif re.match(r"(WCK\d[PN]|A6)_[A-D]$", tail):
            s.nc(u, num)
        elif re.match(r"CKB?_[A-D]$", tail):
            s.net(u, num, ch + ("CLKN_" if tail.startswith("CKB") else "CLKP_") + tail[-1], kind="global")
        elif re.match(r"LP4/4X_CKE\d/LP5_CS\d_[A-D]$", tail):
            cke = "%sCKE%s_%s" % (ch, tail[10], tail[-1])
            s.net(u, num, cke + "_SOC")
            a.res("49.9R 1%", cke + "_SOC", cke, globals_=(cke,))       # close to the memory chip
        elif re.match(r"RESET_[A-D]$", tail):
            if name == "DDR_CH0_RESET_A":
                s.net(u, num, "DDR_RESET", kind="global", shape="output")
            else:
                s.nc(u, num)
        elif re.match(r"ZQ_[A-D]$", tail):
            zq = "ZQ_SOC_%s" % tail[-1]
            s.net(u, num, zq)
            a.res("240R 1%", zq, "VDDQ_DDR_S0", globals_=("VDDQ_DDR_S0",))
        elif tail == "PLL_DVDD":
            s.net(u, num, "VDDA_DDR_PLL_S0", kind="global", shape="input")
        elif tail == "PLL_AVDD1V8":
            s.net(u, num, "VCCA_1V8_S0", kind="global", shape="input")
        elif re.match(r"VDD_(MIF_)?\d$", tail):
            s.net(u, num, "VDD_DDR_S0", kind="global", shape="input")
        elif tail == "VDDQ_CKE":
            s.net(u, num, "VDDQ_DDR_CKE_S3", kind="global", shape="input")
        elif tail == "VDDQ_CK":
            s.net(u, num, "VDDQ_DDR_CK_S0", kind="global", shape="input")
        elif re.match(r"VDDQ_\d$", tail):
            s.net(u, num, "VDDQ_DDR_S0", kind="global", shape="input")
        else:
            raise SystemExit("ddr%d: no rule for ball %s (%s)" % (channel, num, name))
    a.gap()

    # ---- memory chip ---------------------------------------------------------
    chip_id, chip_fp = vendor_part("C2920257", power=r"^VDD|^VSS")
    m = s.place(chip_id, ref("U"), "LPDDR4X 200-ball", 431.8, 162.56, chip_fp,
                fields={"LCSC": "C2920257", "Part": "Samsung K4UBE3D4AA-MGCL (4 GB); any JEDEC 200-ball LPDDR4X fits"})
    for pin in list(m.pins):
        name, num = pin["name"], pin["number"]
        if num in m.assigned:
            continue
        half = {"a": halves[0], "b": halves[1]}.get(name[-1:], "")
        net = dram_net(name, channel, half) if half else None
        if net:
            s.net(m, num, ddr_net(net), kind="global")
        elif name.startswith("ODT_CA"):
            odt = "ODT_%s" % half
            s.net(m, num, odt)
            a.res("10K", odt, "VDD2_DDR_S3", globals_=("VDD2_DDR_S3",))
        elif name in ("ZQ0", "ZQ1"):
            zq = "ZQ_MEM%d_%s" % (channel, name[-1])
            s.net(m, num, zq)
            a.res("240R 1%", zq, "VDDQ_DDR_S0", globals_=("VDDQ_DDR_S0",))
        elif name == "RESET_n":
            s.net(m, num, "DDR_RESET", kind="global", shape="input")
        elif name == "VDD1":
            s.net(m, num, "VCC_1V8_S3", kind="global", shape="input")
        elif name == "VDD2":
            s.net(m, num, "VDD2_DDR_S3", kind="global", shape="input")
        elif name == "VDDQ":
            s.net(m, num, "VDDQ_DDR_S0", kind="global", shape="input")
        elif name == "VSS":
            s.net(m, num, "GND", kind="power")
        elif name == "DNU":
            s.nc(m, num)
        else:
            raise SystemExit("ddr%d memory chip: no rule for ball %s (%s)" % (channel, num, name))
    a.gap()

    def caps(row, rail, values):
        for value in values:
            fp = FP_C0603 if value in ("10uF", "22uF") else FP_C0402
            row.cap(value, rail, "GND", fp, globals_=(rail,))
        row.gap()

    # processor-side decoupling for this channel (reference sheet 12)
    caps(a, "VDDQ_DDR_S0", ["10uF", "1uF", "1uF", "100nF", "100nF", "100nF"])
    caps(a, "VDDQ_DDR_CK_S0", ["1uF"] if channel == 0 else ["1uF", "10uF"])
    caps(a, "VCCA_1V8_S0", ["1uF"])
    caps(a, "VDDA_DDR_PLL_S0", ["1uF"])
    caps(a, "VDDQ_DDR_CKE_S3", ["1uF"])
    caps(a, "VDD_DDR_S0", ["10uF", "4.7uF", "100nF", "1uF", "100nF"])
    # memory-chip decoupling (reference sheet 4)
    caps(b, "VCC_1V8_S3", ["10uF", "10uF"] + ["100nF"] * 7)
    caps(b, "VDD2_DDR_S3", ["22uF", "10uF", "10uF", "1uF", "1uF"] + ["100nF"] * 10)
    caps(b, "VDDQ_DDR_S0", ["22uF", "10uF", "10uF", "1uF", "1uF"] + ["100nF"] * 14)
    if channel == 0:
        # shared items, drawn once: supply links (reference R1204, R1205) and the memory-rail sense tie
        a.res("0R", "VDDQ_DDR_S0", "VDDQ_DDR_CK_S0", globals_=("VDDQ_DDR_S0", "VDDQ_DDR_CK_S0"))
        a.flag("VDDQ_DDR_CK_S0", "global")
        a.res("0R", "VDD2_DDR_S3", "VDDQ_DDR_CKE_S3", globals_=("VDD2_DDR_S3", "VDDQ_DDR_CKE_S3"))
        a.flag("VDDQ_DDR_CKE_S3", "global")
        tie = s.place("Device:NetTie_2", ref("NT"), "sense tie", a.x + 15.24, a.y, "NetTie:NetTie-2_SMD_Pad0.5mm")
        glob(s, tie, {"1": "VDD_DDR_S0", "2": "VDD_DDR_S0_FB"}, "passive")
    return s


# ------------------------------------------------------- processor GPIO plan --
# What each RK3588 GPIO does on this board. Anything not listed is left unconnected.
# Pins shared with the Radxa Rock 5B keep the reference's function (sheets 11, 13, 19), so its
# Linux device tree is a close starting point. Entries are a net name, or
# ("series", resistor, net) or ("divider", series resistor, net, resistor to ground).
GPIO_USE = {
    # bank 0, PMUIO1 domain (1.8 V only): power chip control, as the reference
    "GPIO0_A1": "TSADC_SHUT_H",
    "GPIO0_A2": ("series", "22R", "PMIC_PWR_CTRL1"),
    "GPIO0_A3": "CPU_BIG0_VSEL",
    "GPIO0_A5": ("series", "22R", "PMIC_SPI_CLK"),
    "GPIO0_A6": ("series", "22R", "PMIC_SPI_MOSI"),
    "GPIO0_A7": "PMIC_INT_L",
    "GPIO0_B0": "RTC_INT_L",
    "GPIO0_B1": "PMIC_SPI_CS",
    "GPIO0_B3": "PMIC_SPI_MOSI",       # the reference ties SPI2 data-in to the power chip's single data line
    # bank 0, PMUIO2 domain (3.3 V)
    "GPIO0_B5": "UART2_TX_DEBUG", "GPIO0_B6": "UART2_RX_DEBUG",
    "GPIO0_B7": "MODEM_RESET_H",       # this board; high = reset, through a transistor on the modem sheet
    "GPIO0_C0": "FAN_PWM",
    "GPIO0_C1": "NPU_VSEL",
    "GPIO0_C2": ("divider", "100K", "PMIC_PWR_CTRL3", "120K"),
    "GPIO0_C3": ("divider", "100K", "PMIC_PWR_CTRL2", "120K"),
    "GPIO0_C4": "WIFI_DISABLE_L", "GPIO0_C5": "BT_DISABLE_L", "GPIO0_C6": "MODEM_DISABLE_L",   # this board
    "GPIO0_C7": "I2C6_SDA_M0", "GPIO0_D0": "I2C6_SCL_M0",
    "GPIO0_D1": "I2C0_SCL_M2", "GPIO0_D2": "I2C0_SDA_M2",
    "GPIO0_D3": "MODEM_PWR_EN",        # this board
    "GPIO0_D4": "I2C1_SCL_M2", "GPIO0_D5": "I2C1_SDA_M2",
    "GPIO0_D6": "CPU_BIG1_VSEL",
    # bank 2, EMMCIO domain (1.8 V): eMMC, as the reference
    "GPIO2_A0": "EMMC_CMD", "GPIO2_A1": "EMMC_CLK", "GPIO2_A2": "EMMC_DS", "GPIO2_A3": "EMMC_RST_L",
    "GPIO2_D0": "EMMC_D0", "GPIO2_D1": "EMMC_D1", "GPIO2_D2": "EMMC_D2", "GPIO2_D3": "EMMC_D3",
    "GPIO2_D4": "EMMC_D4", "GPIO2_D5": "EMMC_D5", "GPIO2_D6": "EMMC_D6", "GPIO2_D7": "EMMC_D7",
    # bank 3, VCCIO5 domain (3.3 V)
    "GPIO3_B0": "PCIE_WIFI_PERST_L", "GPIO3_C7": "PCIE_WIFI_CLKREQ_L",      # as the reference
    "GPIO3_B4": "PD1_INT_L", "GPIO3_B2": "PD2_INT_L",
    "GPIO3_B1": "MODEM_VCC_EN",        # this board; high = modem supply on (pulled low at the converter)
    "GPIO3_B5": "UART3_TX_THREAD", "GPIO3_B6": "UART3_RX_THREAD",           # UART3_M1
    "GPIO3_A6": "THREAD_RESET_L", "GPIO3_A7": "THREAD_BOOT",
    "GPIO3_B7": "SPI1_MOSI_TPM", "GPIO3_C0": "SPI1_MISO_TPM", "GPIO3_C1": "SPI1_CLK_TPM",   # SPI1_M1
    "GPIO3_C2": "SPI1_CS0_TPM", "GPIO3_C3": "TPM_INT_L",
    # bank 4, VCCIO6 domain (3.3 V): PCIe control on each controller's own M1 pins
    "GPIO4_B6": "PCIE_NVME_PERST_L", "GPIO4_B4": "PCIE_NVME_CLKREQ_L", "GPIO4_B5": "PCIE_WAKE_L",
    "GPIO4_A5": "PCIE_ETH1_PERST_L", "GPIO4_A3": "PCIE_ETH1_CLKREQ_L",
    "GPIO4_A2": "PCIE_ETH2_PERST_L", "GPIO4_A0": "PCIE_ETH2_CLKREQ_L",
    "GPIO4_B0": "PCIE_ACCEL_PERST_L", "GPIO4_C1": "PCIE_ACCEL_CLKREQ_L",
    "GPIO4_A6": "USBC1_SBU1_DC", "GPIO4_A7": "USBC1_SBU2_DC",               # as the reference (port 1)
    "GPIO4_B7": "USBC2_SBU1_DC", "GPIO4_C0": "USBC2_SBU2_DC",
    "GPIO4_B1": "USB_HOST_PWREN_H",
    "GPIO4_A4": "USBC2_VBUS_EN",       # this board
    "GPIO4_B2": "I2C7_SCL_M3", "GPIO4_B3": "I2C7_SDA_M3",
}


def gpio_bank(s, bank, x, y, row):
    """Place one GPIO bank unit of the processor and wire it from GPIO_USE."""
    u = s.place("soc:RK3588", SOC_REF, "RK3588", x, y, rk3588_symbol.FOOTPRINT, unit=6 + bank)
    for pin in list(u.pins):
        gid = re.search(r"GPIO\d_[A-D]\d", pin["name"]).group(0)
        use = GPIO_USE.get(gid)
        if use is None:
            s.nc(u, pin["number"])
        elif isinstance(use, str):
            s.net(u, pin["number"], use, kind="global")
        else:
            node = gid + "_PIN"
            s.net(u, pin["number"], node)
            row.res(use[1], node, use[2], globals_=(use[2],))
            if use[0] == "divider":
                row.res(use[3], use[2], "GND", globals_=(use[2],))
    return u


def sheet_soc_system():
    """Clock, reset, IO-bank supplies, ADC and GPIO bank 0 (Radxa Rock 5B v1.45 sheets 11, 13, 15, 19)."""
    s = project.sheet("soc_system", "Processor: clock, reset, IO supplies, GPIO bank 0", paper="A2")
    s.text("RK3588 units 12 (system) and 6 (GPIO bank 0), from the Radxa Rock 5B v1.45 schematic, sheets 11, 13, 15 and 19.\\n"
           "IO bank voltages as the reference: banks on VCCIO5 and VCCIO6 run at 3.3 V, PMUIO2 at 3.3 V, the rest at 1.8 V.\\n"
           "Boot select (SARADC_IN0) has only the 100K pull-up: boot order SPI flash, eMMC, SD, USB. Shorting J to ground\\n"
           "forces USB download mode. No SD card slot and no SPI flash on this board, so their pins are left open.\\n"
           "PMUIO and memory VDD1 use VCC_1V8_S3 directly (the reference has a zero-ohm link to VCC1V8_PMU_DDR_S3).", 15, 15)
    a = Row(s, 25.4, 289.56)
    b = Row(s, 25.4, 345.44)
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 127.0, 76.2, rk3588_symbol.FOOTPRINT, unit=12)
    supply = {"OSC_1V8": "VCCA_1V8_S0", "PLL_DVDD0V75": "VDD_0V75_S0", "PLL_AVDD1V8": "VCCA_1V8_S0",
              "PMUIO1_1V8": "VCC_1V8_S3", "PMUIO2_1V8": "VCC_1V8_S3", "PMU_0V75": "VDD_0V75_S3",
              "PMUIO2": "VCC_3V3_S3", "OTP_VDDOTP_0V75": "VDD_0V75_S0", "SARADC_AVDD_1V8": "VCCA_1V8_S0",
              "VCCIO1_1V8": "VCC_1V8_S0", "VCCIO2_1V8": "VCC_1V8_S0", "VCCIO3_1V8": "VCC_1V8_S0",
              "VCCIO4_1V8": "VCC_1V8_S0", "VCCIO4": "VCC_1V8_S0", "VCCIO5_1V8": "VCC_1V8_S0",
              "VCCIO6_1V8": "VCC_1V8_S0", "VCCIO5": "VCC_3V3_S0", "VCCIO6": "VCC_3V3_S0",
              "VCCIO2": "VCCIO_SD_S0", "EMMCIO_1V8": "VCC_1V8_S3"}
    extra_cap = {"OSC_1V8": "1uF", "PLL_DVDD0V75": "1uF", "PMU_0V75": "1uF"}
    for pin in list(u.pins):
        name, num = pin["name"], pin["number"]
        if name in supply:
            rail = supply[name]
            s.net(u, num, rail, kind="global", shape="input")
            b.cap("1uF" if name == "EMMCIO_1V8" else "100nF", rail, "GND", globals_=(rail,))
            if name in extra_cap:
                b.cap(extra_cap[name], rail, "GND", globals_=(rail,))
        elif name == "XOUT_24M":
            s.net(u, num, "XOUT24M")
        elif name == "XIN_24M":
            s.net(u, num, "XIN24M")
        elif name == "NPOR_u":
            s.net(u, num, "RESET_L", kind="global", shape="input")
        elif name == "TVSS_d":
            s.net(u, num, "GND", kind="power")
        elif name == "SARADC_IN0_BOOT":
            s.net(u, num, "BOOT_SARADC_IN0")
        elif name == "SARADC_IN1":
            s.net(u, num, "RECOVERY_KEY", kind="global", shape="input")
        elif name in ("OTP_VPP", "TSADC_TEST_OUT_TS") or re.match(r"SARADC_IN[2-7]$", name):
            s.nc(u, num)
        else:
            raise SystemExit("soc_system: no rule for ball %s (%s)" % (num, name))
    # 24 MHz crystal (reference Y1100, R1101, R1103, C1101, C1102)
    y = s.place("Device:Crystal_GND24", ref("Y"), "24MHz", 76.2, 215.9, "Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm")
    s.nets(y, {"1": "XTAL_X1", "3": "XIN24M"})
    pwr(s, y, {"2": "GND", "4": "GND"})
    a.res("22R", "XOUT24M", "XTAL_X1")
    a.res("510K 1%", "XOUT24M", "XIN24M")
    a.cap("18pF", "XTAL_X1", "GND")
    a.cap("18pF", "XIN24M", "GND")
    a.gap()
    # reset (reference C1100, R1100) and boot / recovery inputs (reference sheet 15)
    a.cap("100nF", "RESET_L", "GND", globals_=("RESET_L",))
    a.res("0R", "RESET_L", "TSADC_SHUT_H", globals_=("RESET_L", "TSADC_SHUT_H"))
    a.res("100K", "VCCA_1V8_S0", "BOOT_SARADC_IN0", globals_=("VCCA_1V8_S0",))
    a.res("10K", "VCCA_1V8_S0", "RECOVERY_KEY", globals_=("VCCA_1V8_S0", "RECOVERY_KEY"))
    a.cap("1nF", "RECOVERY_KEY", "GND", globals_=("RECOVERY_KEY",))
    a.gap()
    j = s.place("Connector_Generic:Conn_01x02", ref("J"), "USB download", 177.8, 215.9,
                "Connector_PinHeader_2.54mm:PinHeader_1x02_P2.54mm_Vertical", passive=True)
    s.nets(j, {"1": "BOOT_SARADC_IN0"})
    pwr(s, j, {"2": "GND"})
    # GPIO bank 0 and its I2C pull-ups (reference: 2.2K to VCC_3V3_S3)
    gpio_bank(s, 0, 368.3, 76.2, a)
    a.gap()
    for net in ("I2C0_SCL_M2", "I2C0_SDA_M2", "I2C1_SCL_M2", "I2C1_SDA_M2", "I2C6_SCL_M0", "I2C6_SDA_M0"):
        a.res("2.2K", "VCC_3V3_S3", net, globals_=("VCC_3V3_S3", net))
    return s


def sheet_soc_gpio(first):
    """Two GPIO bank units per sheet."""
    s = project.sheet("soc_gpio%d%d" % (first, first + 1), "Processor: GPIO banks %d and %d" % (first, first + 1), paper="A2")
    notes = {1: "Bank 1 (1.8 V) is unused on this board. Bank 2 carries the eMMC interface, as the reference;\\n"
                "its other pins (1.8 V) are unused. The eMMC chip itself is not drawn yet.",
             3: "Banks 3 and 4 run at 3.3 V (pins GPIO4_C2-C6 at 1.8 V, GPIO4_D0-D5 on the SD supply: unused).\\n"
                "PCIe reset and clock-request lines sit on each controller's own M1 pins. Assignments are in GPIO_USE\\n"
                "in build.py; those marked 'this board' are new and not from the reference."}
    s.text(notes[first], 15, 15)
    row = Row(s, 25.4, 330.2)
    gpio_bank(s, first, 152.4, 60.96, row)
    gpio_bank(s, first + 1, 406.4, 60.96, row)
    if first == 3:
        for net in ("I2C7_SCL_M3", "I2C7_SDA_M3"):
            row.res("2.2K", "VCC_3V3_S0", net, globals_=("VCC_3V3_S0", net))
    return s


# ---------------------------------------------------------------- sheet 17 --
# 100 MHz PCIe reference clock: one oscillator, two 4-output buffers (Radxa Rock 5B v1.45 sheet 7 has one).
# Buffer outputs: (output pin pair, net prefix) -- None = unused output.
CLOCK_OUTPUTS = {
    "A": [("CLKoutA0", "PCIE30_PHY0_REFCLK"), ("CLKoutB0", "PCIE30_PHY1_REFCLK"),
          ("CLKoutA1", "PCIE_NVME_REFCLK"), ("CLKoutB1", "PCIE_ACCEL_REFCLK")],
    "B": [("CLKoutA0", "PCIE_ETH1_REFCLK"), ("CLKoutA1", "PCIE_ETH2_REFCLK"),
          ("CLKoutB0", None), ("CLKoutB1", None)],
}


def sheet_pcie_clock():
    s = project.sheet("pcie_clock", "PCIe reference clock: oscillator and two buffers", paper="A2")
    s.text("Each buffer circuit is copied from the Radxa Rock 5B v1.45 schematic, sheet 7 (Au5426, same pinout as TI LMK00304).\\n"
           "Straps as the reference: input 0 selected, HCSL outputs, reference output off. Outputs have 33R in series\\n"
           "and 49.9R to ground on each leg. Differences from the reference, to check against the buffer datasheet:\\n"
           "  - two buffers share the one oscillator (the reference has a single buffer);\\n"
           "  - each regulator is always enabled (the reference switches it from a GPIO);\\n"
           "  - the zero-ohm links between the regulator and the four supply pins groups are left out;\\n"
           "  - two outputs of buffer B are unused and left open.\\n"
           "The Wi-Fi slot does not use this clock: its reference clock comes from the processor's combo PHY.", 15, 15)
    buf_id, buf_fp = vendor_part("C200359", power=r"^VCC|GND|^EP$")
    rows = {"A": Row(s, 25.4, 304.8), "B": Row(s, 25.4, 360.68)}
    for i, x in enumerate("AB"):
        t = "CK%s_" % x
        rail = "VCC3V3_CLK" + x
        row = rows[x]
        g = (rail,)
        # 3.3 V regulator for this buffer (reference U20 RT9193-33, C590-C592, R410)
        ldo = s.place("Regulator_Linear:AP2112K-3.3", ref("U"), "RT9193-33GB", 76.2 + i * 254.0, 96.52,
                      "Package_TO_SOT_SMD:SOT-23-5")
        glob(s, ldo, {"VIN": "VCC5V0_SYS"}, "input")
        pwr(s, ldo, {"GND": "GND"})
        s.nets(ldo, {"EN": t + "LDO_EN"})
        glob(s, ldo, {"VOUT": rail}, "output")
        row.cap("1uF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
        row.res("10K", "VCC5V0_SYS", t + "LDO_EN", globals_=("VCC5V0_SYS",))
        row.cap("10uF", rail, "GND", FP_C0603, globals_=g)
        row.cap("1uF", rail, "GND", globals_=g)
        row.gap()
        u = s.place(buf_id, ref("U"), "Au5426 / LMK00304", 177.8 + i * 254.0, 152.4, buf_fp,
                    fields={"LCSC": "C200359 (TI LMK00304SQ, pin-compatible)"})
        glob(s, u, {"VCC": rail, "VCCOA": rail, "VCCOB": rail, "VCCOC": rail}, "input")
        pwr(s, u, {"GND": "GND", "EP": "GND"})
        glob(s, u, {"CLKin0": "GEN_CLK_100MHZ"}, "input")
        s.nets(u, {"CLKin0*": t + "IN0_N", "OSCout": t + "OSCOUT", "CLKin_SEL0": t + "SEL0", "CLKin_SEL1": t + "SEL1",
                   "CLKout_TYPE0": t + "TYPE0", "CLKout_TYPE1": t + "TYPE1", "REFout_EN": t + "REF_EN",
                   "REFout": t + "REFOUT"})
        s.nc(u, "CLKin1", "CLKin1*", "OSCin", "NC")
        for value in ["22uF", "100nF", "1uF"] * 4 + ["100nF"] * 7:      # four supply groups, then at the pins
            row.cap(value, rail, "GND", FP_C0603 if value == "22uF" else FP_C0402, globals_=g)
        row.gap()
        row.cap("100nF", t + "IN0_N", "GND")
        row.cap("100nF", t + "OSCOUT", "GND")
        row.res("1K", t + "SEL0", "GND")
        row.res("1K", t + "SEL1", "GND")
        row.res("1K", t + "TYPE0", "GND")
        row.res("1K", rail, t + "TYPE1", globals_=g)
        row.res("1K", t + "REF_EN", "GND")
        row.res("1K", t + "REFOUT", "GND")
        row.gap()
        for pin, net in CLOCK_OUTPUTS[x]:
            if net is None:
                s.nc(u, pin, pin + "*")
                continue
            for leg, suffix in ((pin, "_P"), (pin + "*", "_N")):
                node = "%s%s%s" % (t, pin, suffix)
                s.net(u, leg, node)
                row.res("33R", node, net + suffix, globals_=(net + suffix,))
                row.res("49.9R 1%", net + suffix, "GND", globals_=(net + suffix,))
    # 100 MHz oscillator, shared (reference Y1101, FB1, R90584/85, R90613/14, C90430)
    a = rows["A"]
    a.gap()
    osc = s.place("Oscillator:ASE-xxxMHz", ref("Y"), "100MHz 3.3V 3225", 76.2, 190.5,
                  "Oscillator:Oscillator_SMD_Abracon_ASE-4Pin_3.2x2.5mm")
    s.nets(osc, {"Vdd": "OSC_VDD", "EN": "OSC_EN", "OUT": "OSC_OUT"})
    pwr(s, osc, {"GND": "GND"})
    bead = s.place("Device:FerriteBead", ref("FB"), "120R@100MHz 0.6A", a.x, a.y, "Inductor_SMD:L_0402_1005Metric")
    glob(s, bead, {"1": "VCC3V3_CLKA"}, "passive")
    s.nets(bead, {"2": "OSC_VDD"})
    a.x += a.pitch
    a.flag("OSC_VDD")
    a.cap("100nF", "OSC_VDD", "GND")
    a.res("10K", "OSC_VDD", "OSC_EN")
    a.res("33R", "OSC_OUT", "OSC_BIAS")
    a.res("100R 1%", "VCC3V3_CLKA", "OSC_BIAS", globals_=("VCC3V3_CLKA",))
    a.res("100R 1%", "OSC_BIAS", "GND")
    a.cap("100nF", "OSC_BIAS", "GEN_CLK_100MHZ", globals_=("GEN_CLK_100MHZ",))
    return s


# ---------------------------------------------------------------- sheet 18 --
def sheet_soc_display():
    """Display and camera blocks, which this board does not use."""
    s = project.sheet("soc_display", "Processor: display and camera blocks (unused)", paper="A2")
    s.text("RK3588 unit 5: HDMI/eDP transmitters, HDMI receiver, MIPI CSI/DSI. None is used on this board\\n"
           "(setup video goes out over USB-C DisplayPort from the Type-C PHYs).\\n"
           "Supply pins are powered from the same rails as on the Radxa Rock 5B v1.45 schematic (sheets 16, 17), with one\\n"
           "100 nF each; all signal, REXT and VREG pins are left open. Two rails were not readable from the reference and are\\n"
           "assigned by voltage (HDMI/eDP AVDD_0V75, HDMI_RX_DVDD). Confirm this unused-block treatment against\\n"
           "Rockchip's hardware design guide before layout.", 15, 15)
    u = s.place("soc:RK3588", SOC_REF, "RK3588", 203.2, 60.96, rk3588_symbol.FOOTPRINT, unit=5)
    row = Row(s, 25.4, 381.0)
    for pin in list(u.pins):
        name, num = pin["name"], pin["number"]
        if pin["type"] != "power_in":
            s.nc(u, num)
            continue
        if name.startswith("HDMI/eDP_TX"):
            rail = "VCC_1V8_S0" if name.endswith("_1V8") else "VDDA_0V75_S0"
        elif name.startswith("HDMI_RX"):
            rail = "VDDA_0V75_S0" if name.endswith("0V75") else "VCCA_3V3_S0"
        elif name.startswith("MIPI_CSI"):
            rail = "VCC_1V8_S0" if name.endswith("1V8") else "VDD_0V75_S0"
        elif name.startswith("MIPI_D/C_PHY"):
            rail = {"VDD": "VDD_0V75_S0", "1V2": "VDDA_1V2_S0", "1V8": "VCC_1V8_S0"}[name.rsplit("_", 1)[1]]
        else:
            raise SystemExit("soc_display: no rule for supply ball %s (%s)" % (num, name))
        s.net(u, num, rail, kind="global", shape="input")
        row.cap("100nF", rail, "GND", globals_=(rail,))
    return s


# ------------------------------------------------------------ sheets 19, 20 --
def sheet_usbc(n):
    """One USB-C port with DisplayPort alt mode, copied from Radxa Rock 5B v1.45 sheet 29."""
    t = "USBC%d_" % n
    bus = {1: "I2C6_%s_M0", 2: "I2C7_%s_M3"}[n]
    s = project.sheet("usbc%d" % n, "USB-C port %d: USB 3, DisplayPort, power %s" % (n, "in" if n == 1 else "out"))
    s.text("Copied from the Radxa Rock 5B v1.45 schematic, sheet 29 (its one Type-C port).\\n"
           + ("Port 1 is the power-input port: %sVBUS goes to the power-entry circuit, which is not drawn yet.\\n" % t if n == 1 else
              "Port 2 sources 5 V: SY6280AAC switch as on the reference's USB host port (sheet 27), limit 6800 / 3.4K = 2 A.\\n"
              "The reference has no sourcing Type-C port, so this switch arrangement is new for this board.\\n")
           + "Left out: the common-mode choke on the USB 2 pair, the zero-ohm links, and the input-voltage ADC divider.\\n"
           "ESD parts: TPD4E05U06 for the reference's ESD73034D, generic dual TVS for its ESD5302F: confirm equivalents.\\n"
           "The interrupt pull-up goes to 3.3 V to match the GPIO bank (the reference pulls it to 1.8 V).\\n"
           "The processor's OTG ID ball is unused: the port's role comes from the PD controller.", 15, 15)
    j = s.place("Connector:USB_C_Receptacle", ref("J"), "USB-C", 330.2, 139.7,
                "Connector_USB:USB_C_Receptacle_Amphenol_12401610E4-2A", passive=True,
                fields={"Part": "Amphenol 12401610E4-2A, USB Type-C receptacle, 24 positions"})
    glob(s, j, {"VBUS": t + "VBUS"}, "passive")
    pwr(s, j, {"GND": "GND", "SH": "GND"})
    s.nets(j, {"CC1": t + "CC1", "CC2": t + "CC2", "SBU1": t + "AUX_P", "SBU2": t + "AUX_N",
               "D+": t + "CONN_DP", "D-": t + "CONN_DM",
               "A2": t + "TX1C_P", "A3": t + "TX1C_N", "B2": t + "TX2C_P", "B3": t + "TX2C_N"})
    glob(s, j, {"B11": t + "SSRX1_P", "B10": t + "SSRX1_N", "A11": t + "SSRX2_P", "A10": t + "SSRX2_N"})
    a = Row(s, 25.4, 220.98)
    b = Row(s, 25.4, 264.16)
    for lane in "12":
        for pol in "PN":
            a.cap("100nF", "%sSSTX%s_%s" % (t, lane, pol), "%sTX%sC_%s" % (t, lane, pol),
                  globals_=("%sSSTX%s_%s" % (t, lane, pol),))
    a.gap()
    for pol, sbu in (("P", "1"), ("N", "2")):                 # DisplayPort side channel on SBU
        a.cap("100nF", t + "SBU" + sbu, t + "AUX_" + pol, globals_=(t + "SBU" + sbu,))
        a.res("2M", t + "AUX_" + pol, "GND")
        a.res("100K", "%sSBU%s_DC" % (t, sbu), t + "AUX_" + pol, globals_=("%sSBU%s_DC" % (t, sbu),))
    a.gap()
    a.res("2.2R", t + "USB2_DP", t + "CONN_DP", globals_=(t + "USB2_DP",))
    a.res("2.2R", t + "USB2_DM", t + "CONN_DM", globals_=(t + "USB2_DM",))
    a.res("4.7K", "VCCA_3V3_S0", t + "VBUSDET", globals_=("VCCA_3V3_S0", t + "VBUSDET"))
    a.gap()
    # ESD protection
    for k, (rxp, rxn, txp, txn) in enumerate(((t + "SSRX1_P", t + "SSRX1_N", t + "TX1C_P", t + "TX1C_N"),
                                              (t + "SSRX2_P", t + "SSRX2_N", t + "TX2C_P", t + "TX2C_N"))):
        e = s.place("Power_Protection:TPD4E05U06DQA", ref("U"), "TPD4E05U06", 190.5, 96.52 + k * 50.8,
                    "Package_SON:USON-10_2.5x1.0mm_P0.5mm")
        glob(s, e, {"1": rxp, "2": rxn})
        s.nets(e, {"4": txp, "5": txn})
        pwr(s, e, {"3": "GND", "8": "GND"})
        s.nc(e, "6", "7", "9", "10")
    for k, (n1, n2) in enumerate(((t + "CONN_DP", t + "CONN_DM"), (t + "CC1", t + "CC2"), (t + "AUX_P", t + "AUX_N"))):
        d = s.place("Device:D_TVS_Dual_AAC", ref("D"), "ESD5302F", 96.52 + k * 30.48, 165.1,
                    "Package_TO_SOT_SMD:SOT-23")
        s.nets(d, {"A1": n1, "A2": n2})
        pwr(s, d, {"common": "GND"})
    # USB-C power-delivery controller
    pd = s.place("Interface_USB:FUSB302BMPX", ref("U"), "FUSB302BMPX", 81.28, 99.06,
                 "Package_DFN_QFN:WQFN-14-1EP_2.5x2.5mm_P0.5mm_EP1.45x1.45mm")
    s.nets(pd, {"10": t + "CC1", "11": t + "CC1", "1": t + "CC2", "14": t + "CC2"})
    glob(s, pd, {"2": t + "VBUS"}, "input")
    glob(s, pd, {"12": "VCC5V0_SYS", "13": "VCC5V0_SYS", "3": "VCC_3V3_S3", "4": "VCC_3V3_S3"}, "input")
    pwr(s, pd, {"8": "GND", "9": "GND", "15": "GND"})
    glob(s, pd, {"6": bus % "SCL", "7": bus % "SDA", "5": "PD%d_INT_L" % n})
    b.cap("220pF", t + "CC1", "GND")
    b.cap("220pF", t + "CC2", "GND")
    b.cap("100nF", "VCC_3V3_S3", "GND", globals_=("VCC_3V3_S3",))
    b.cap("1uF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
    b.cap("100nF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
    b.res("10K", "VCC_3V3_S0", "PD%d_INT_L" % n, globals_=("VCC_3V3_S0", "PD%d_INT_L" % n))
    if n == 2:
        b.gap()
        part_id, fp = vendor_part("C55136", power=r"^IN$|GND", types=[(r"^OUT$", "power_out")])
        sw = s.place(part_id, ref("U"), "SY6280AAC", 81.28, 190.5, fp, fields={"LCSC": "C55136"})
        glob(s, sw, {"IN": "VCC5V0_SYS"}, "input")
        glob(s, sw, {"OUT": t + "VBUS"}, "output")
        pwr(s, sw, {"GND": "GND"})
        glob(s, sw, {"EN": t + "VBUS_EN"}, "input")
        s.nets(sw, {"ISET": t + "ISET"})
        b.cap("1uF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
        b.res("100K", t + "VBUS_EN", "GND", globals_=(t + "VBUS_EN",))
        b.res("3.4K 1%", t + "ISET", "GND")
        b.cap("10uF", t + "VBUS", "GND", FP_C0603, globals_=(t + "VBUS",))
        b.cap("100nF", t + "VBUS", "GND", globals_=(t + "VBUS",))
    return s


# ---------------------------------------------------------------- sheet 21 --
def sheet_usb_hub():
    """USB 2.0 hub and the two USB-A ports (Radxa Rock 5B v1.45 sheets 9 and 27)."""
    s = project.sheet("usb_hub", "USB 2.0 hub and USB-A ports")
    s.text("Hub copied from the Radxa Rock 5B v1.45 schematic, sheet 9 (FE1.1s, powered from 3.3 V: VDD5 has only\\n"
           "its capacitors, as the hub's datasheet requires). USB-A power switch copied from sheet 27.\\n"
           "Hub ports: 1 and 2 = USB-A, 3 = USB 2 side of the 5G modem slot, 4 = spare.\\n"
           "The USB-A ports are USB 2.0 only. The processor's one spare USB 3 port goes straight to the modem slot;\\n"
           "USB 3 on the USB-A ports would need a USB 3 hub chip, for which the reference has no circuit.\\n"
           "One switch feeds both USB-A ports, limit 6800 / 3.4K = 2 A (the reference sets 1 A).\\n"
           "Left out: the common-mode chokes on the USB-A data pairs. ESD parts are generic substitutes.", 15, 15)
    hub_id, hub_fp = vendor_part("C6776948", power=r"^VD33F$|^VSS$")
    u = s.place(hub_id, ref("U"), "FE1.1s", 129.54, 116.84, hub_fp, fields={"LCSC": "C6776948"})
    glob(s, u, {"DPU": "USB2_HUB_DP", "DMU": "USB2_HUB_DM"})
    s.nets(u, {"DP1": "USBA1_DP", "DM1": "USBA1_DM", "DP2": "USBA2_DP", "DM2": "USBA2_DM"})
    glob(s, u, {"DP3": "USB2_MODEM_DP", "DM3": "USB2_MODEM_DM"})
    s.nets(u, {"VD33F": "HUB_3V3", "VDD5": "HUB_VDD5", "XIN": "HUB_XIN", "XOUT": "HUB_XOUT", "REXT": "HUB_REXT",
               "OVCJ": "HUB_OVCJ", "XRSTJ": "HUB_XRSTJ", "VBUSM": "HUB_VBUSM", "BUSJ": "HUB_BUSJ", "DRV": "HUB_DRV"})
    pwr(s, u, {"VSS": "GND"})
    s.nc(u, "DP4", "DM4", "TESTJ", "LED1", "LED2", "PWRJ")
    y = s.place("Device:Crystal_GND24", ref("Y"), "12MHz 20pF", 53.34, 116.84, "Crystal:Crystal_SMD_3225-4Pin_3.2x2.5mm")
    s.nets(y, {"1": "HUB_XOUT", "3": "HUB_XIN"})
    pwr(s, y, {"2": "GND", "4": "GND"})
    a = Row(s, 25.4, 220.98)
    bead = s.place("Device:FerriteBead", ref("FB"), "120R@100MHz", a.x, a.y, "Inductor_SMD:L_0402_1005Metric")
    glob(s, bead, {"1": "VCC_3V3_S0"}, "passive")
    s.nets(bead, {"2": "HUB_3V3"})
    a.x += a.pitch
    a.flag("HUB_3V3")
    a.cap("22uF", "HUB_3V3", "GND", FP_C0603)
    a.cap("100nF", "HUB_VDD5", "GND")
    a.cap("100nF", "HUB_VDD5", "GND")
    a.cap("56pF", "HUB_VDD5", "GND")
    a.gap()
    a.res("2.7K 1%", "HUB_REXT", "GND")
    a.res("10K", "VCC_3V3_S0", "HUB_OVCJ", globals_=("VCC_3V3_S0",))
    a.res("100K", "VCC_3V3_S0", "HUB_XRSTJ", globals_=("VCC_3V3_S0",))
    a.res("10K", "VCC_3V3_S0", "HUB_VBUSM", globals_=("VCC_3V3_S0",))
    a.cap("100nF", "HUB_VBUSM", "GND")
    a.res("100K", "VCC_3V3_S0", "HUB_BUSJ", globals_=("VCC_3V3_S0",))
    a.res("1K", "VCC_3V3_S0", "HUB_DRV", globals_=("VCC_3V3_S0",))
    a.gap()
    # USB-A supply switch (reference U9, R258, R259, C396-C399, C402)
    sw_id, sw_fp = vendor_part("C55136", power=r"^IN$|GND", types=[(r"^OUT$", "power_out")])
    sw = s.place(sw_id, ref("U"), "SY6280AAC", 248.92, 81.28, sw_fp, fields={"LCSC": "C55136"})
    glob(s, sw, {"IN": "VCC5V0_SYS"}, "input")
    glob(s, sw, {"EN": "USB_HOST_PWREN_H"}, "input")
    pwr(s, sw, {"GND": "GND"})
    s.nets(sw, {"OUT": "USBA_VBUS", "ISET": "USBA_ISET"})
    a.cap("1uF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
    a.res("100K", "USB_HOST_PWREN_H", "GND", globals_=("USB_HOST_PWREN_H",))
    a.res("3.4K 1%", "USBA_ISET", "GND")
    for value in ("22uF", "10uF", "100nF", "100nF"):
        a.cap(value, "USBA_VBUS", "GND", FP_C0603 if value in ("22uF", "10uF") else FP_C0402)
    j = s.place("Connector:USB_A_Stacked", ref("J"), "USB-A x2 stacked", 353.06, 101.6,
                "Connector_USB:USB_A_CUI_UJ2-ADH-TH_Horizontal_Stacked", passive=True,
                fields={"Part": "CUI UJ2-ADH-TH, dual stacked USB 2.0 Type-A receptacle"})
    s.nets(j, {"VBUS1": "USBA_VBUS", "VBUS2": "USBA_VBUS", "D1+": "USBA1_DP", "D1-": "USBA1_DM",
               "D2+": "USBA2_DP", "D2-": "USBA2_DM"})
    pwr(s, j, {"GND1": "GND", "GND2": "GND", "Shield": "GND"})
    for k in (1, 2):
        d = s.place("Device:D_TVS_Dual_AAC", ref("D"), "ESD", 292.1, 86.36 + (k - 1) * 63.5, "Package_TO_SOT_SMD:SOT-23")
        s.nets(d, {"A1": "USBA%d_DP" % k, "A2": "USBA%d_DM" % k})
        pwr(s, d, {"common": "GND"})
    return s


# ---------------------------------------------------------------- sheet 22 --
def sheet_emmc():
    """eMMC storage chip. The reference uses a plug-in eMMC module (Radxa Rock 5B v1.45 sheet 25)."""
    s = project.sheet("emmc", "eMMC storage")
    s.text("The reference has a socket for an eMMC module (sheet 25); this board has the chip soldered down.\\n"
           "From the reference: 10K pull-ups on reset, data 0 and command to VCC_1V8_S3, 10 pF on the clock,\\n"
           "the 3.3 V flash supply from VCC_3V3_S3 and the 1.8 V interface supply from VCC_1V8_S3.\\n"
           "Added for a soldered chip (these sit inside the module on the reference): the 1 uF capacitor on VDDI\\n"
           "and 100 nF capacitors at the supply balls. Check both against the chosen chip's datasheet.\\n"
           "Symbol: Samsung KLMBG2JETD-B041 (32 GB). Any JEDEC 153-ball eMMC 5.1 chip fits the same footprint.", 15, 15)
    chip_id, chip_fp = vendor_part("C2803245", power=r"^VDD$|^VDDF$|^VSS$")
    u = s.place(chip_id, ref("U"), "eMMC 153-ball", 203.2, 127.0, chip_fp,
                fields={"LCSC": "C2803245", "Part": "Samsung KLMBG2JETD-B041"})
    glob(s, u, {"DAT%d" % i: "EMMC_D%d" % i for i in range(8)})
    glob(s, u, {"CDM": "EMMC_CMD", "CLK": "EMMC_CLK", "DATA-STROBE": "EMMC_DS", "RSTN": "EMMC_RST_L"})
    glob(s, u, {"VDD": "VCC_1V8_S3", "VDDF": "VCC_3V3_S3"}, "input")
    s.nets(u, {"VDDI": "EMMC_VDDI"})
    pwr(s, u, {"VSS": "GND"})
    s.nc(u, "NC")
    a = Row(s, 25.4, 241.3)
    for net in ("EMMC_RST_L", "EMMC_D0", "EMMC_CMD"):
        a.res("10K", "VCC_1V8_S3", net, globals_=("VCC_1V8_S3", net))
    a.cap("10pF", "EMMC_CLK", "GND", globals_=("EMMC_CLK",))
    a.gap()
    a.cap("10uF", "VCC_3V3_S3", "GND", FP_C0603, globals_=("VCC_3V3_S3",))
    a.cap("100nF", "VCC_3V3_S3", "GND", globals_=("VCC_3V3_S3",))
    a.cap("100nF", "VCC_3V3_S3", "GND", globals_=("VCC_3V3_S3",))
    a.gap()
    a.cap("4.7uF", "VCC_1V8_S3", "GND", FP_C0603, globals_=("VCC_1V8_S3",))
    a.cap("100nF", "VCC_1V8_S3", "GND", globals_=("VCC_1V8_S3",))
    a.cap("100nF", "VCC_1V8_S3", "GND", globals_=("VCC_1V8_S3",))
    a.gap()
    a.cap("1uF", "EMMC_VDDI", "GND")
    return s


# ---------------------------------------------------------------- sheet 23 --
def sheet_peripherals():
    """RTC, Thread radio, debug serial header and fan."""
    s = project.sheet("peripherals", "RTC, Thread radio, debug port, fan")
    s.text("RTC: copied from the Radxa Rock 5B v1.45 schematic, sheet 5 (HYM8563, pin-compatible with PCF8563).\\n"
           "  Its 32 kHz output also feeds the Wi-Fi slot; the pull-up goes to +3V3 here (1.8 V on the reference).\\n"
           "Fan: copied from sheet 20 (low-side switch on GPIO0_C0 with a flyback diode).\\n"
           "Thread / Matter radio: ESP32-H2-MINI-1 on UART3. Not from the reference: the enable RC, strap pull-ups\\n"
           "  and pin use follow the module datasheet (vendor/lcsc_C18203134). LCSC showed this module out of stock.\\n"
           "Debug port: UART2 at 3.3 V on a three-pin header.\\n"
           "The TPM is on its own sheet.", 15, 15)
    a = Row(s, 25.4, 220.98)
    b = Row(s, 25.4, 264.16)
    # ---- RTC (reference U3, Y2, C224, D1, D2, C228, R117, R116) ---------------
    rtc = s.place("Timer_RTC:PCF8563T", ref("U"), "HYM8563TS", 76.2, 99.06, "Package_SO:TSSOP-8_3x3mm_P0.65mm")
    s.nets(rtc, {"OSCI": "RTC_OSCI", "OSCO": "RTC_OSCO", "VDD": "RTC_VDD"})
    pwr(s, rtc, {"VSS": "GND"})
    glob(s, rtc, {"~{INT}": "RTC_INT_L", "SDA": "I2C6_SDA_M0", "SCL": "I2C6_SCL_M0", "CLKO": "SUSCLK_32K"})
    x = s.place("Device:Crystal", ref("Y"), "32.768kHz", 40.64, 137.16, "Crystal:Crystal_SMD_3215-2Pin_3.2x1.5mm")
    s.nets(x, {"1": "RTC_OSCO", "2": "RTC_OSCI"})
    a.cap("12pF", "RTC_OSCI", "GND")
    for anode, kind in (("VCC_3V3_S3", "global"), ("RTC_BAT", "local")):
        d = s.place("Device:D_Schottky", ref("D"), "B5819WS", a.x, a.y, "Diode_SMD:D_SOD-323")
        s.net(d, "A", anode, kind=kind)
        s.net(d, "K", "RTC_VDD")
        a.x += a.pitch * 2
    a.flag("RTC_VDD")
    a.cap("100nF", "RTC_VDD", "GND")
    a.res("47K", "VCC_1V8_S3", "RTC_INT_L", globals_=("VCC_1V8_S3", "RTC_INT_L"))
    a.res("10K", "+3V3", "SUSCLK_32K", globals_=("SUSCLK_32K",))
    bat = s.place("Connector_Generic:Conn_01x02", ref("J"), "RTC battery 3 V", 127.0, 137.16,
                  "Connector_JST:JST_GH_BM02B-GHS-TBT_1x02-1MP_P1.25mm_Vertical", passive=True)
    s.nets(bat, {"1": "RTC_BAT"})
    pwr(s, bat, {"2": "GND"})
    a.gap()
    # ---- fan (reference Q9518, R95059, R95060, D5001, C90427, C90428) ---------
    q = s.place("Transistor_FET:AO3400A", ref("Q"), "AO3416", 203.2, 109.22, "Package_TO_SOT_SMD:SOT-23")
    s.nets(q, {"G": "FAN_GATE", "S": "FAN_SRC", "D": "FAN_LOW"})
    fan = s.place("Connector_Generic:Conn_01x02", ref("J"), "Fan 5 V", 243.84, 99.06,
                  "Connector_JST:JST_GH_BM02B-GHS-TBT_1x02-1MP_P1.25mm_Vertical", passive=True)
    s.nets(fan, {"1": "FAN_LOW"})
    glob(s, fan, {"2": "VCC5V0_SYS"}, "passive")
    a.res("1K", "FAN_PWM", "FAN_GATE", globals_=("FAN_PWM",))
    a.res("0.1R", "FAN_SRC", "GND")
    d = s.place("Device:D_Schottky", ref("D"), "1N5819", a.x, a.y, "Diode_SMD:D_SOD-123")
    s.net(d, "A", "FAN_LOW")
    s.net(d, "K", "VCC5V0_SYS", kind="global", shape="passive")
    a.x += a.pitch * 2
    a.cap("10uF", "VCC5V0_SYS", "GND", "Capacitor_SMD:C_1206_3216Metric", globals_=("VCC5V0_SYS",))
    a.cap("100nF", "VCC5V0_SYS", "GND", globals_=("VCC5V0_SYS",))
    # ---- debug serial header --------------------------------------------------
    dbg = s.place("Connector_Generic:Conn_01x03", ref("J"), "Debug UART 3.3 V", 243.84, 152.4,
                  "Connector_PinHeader_2.54mm:PinHeader_1x03_P2.54mm_Vertical", passive=True)
    pwr(s, dbg, {"1": "GND"})
    glob(s, dbg, {"2": "UART2_TX_DEBUG", "3": "UART2_RX_DEBUG"})
    # ---- Thread / Matter radio --------------------------------------------------
    mod_id, mod_fp = vendor_part("C18203134", power=r"^3V3$|^VBAT$|^GND$")
    m = s.place(mod_id, ref("U"), "ESP32-H2-MINI-1", 340.36, 124.46, mod_fp, fields={"LCSC": "C18203134"})
    pwr(s, m, {"3V3": "+3V3", "VBAT": "+3V3", "GND": "GND"})
    s.nets(m, {"EN": "THREAD_EN", "IO8": "THREAD_IO8"})
    glob(s, m, {"IO9": "THREAD_BOOT", "TXD0": "UART3_RX_THREAD", "RXD0": "UART3_TX_THREAD"})
    s.nc(m, "NC", "IO0", "IO1", "IO2", "IO3", "IO4", "IO5", "IO10", "IO11", "IO12", "IO13", "IO14",
         "IO22", "IO25", "IO26", "IO27")
    b.cap("10uF", "+3V3", "GND", FP_C0603)
    b.cap("100nF", "+3V3", "GND")
    b.res("10K", "+3V3", "THREAD_EN")
    b.cap("1uF", "THREAD_EN", "GND")
    b.res("0R", "THREAD_RESET_L", "THREAD_EN", globals_=("THREAD_RESET_L",))
    b.res("10K", "+3V3", "THREAD_BOOT", globals_=("THREAD_BOOT",))
    b.res("10K", "+3V3", "THREAD_IO8")
    return s


# ---------------------------------------------------------------- sheet 24 --
def sheet_power_entry():
    """DC jack and USB-C port 1 joined onto VIN through two ideal diodes. Not from the reference."""
    s = project.sheet("power_entry", "Power entry: DC jack and USB-C input")
    s.text("NEW FOR THIS BOARD, not copied from the reference (which has a single USB-C input wired straight to its converters).\\n"
           "Each source reaches VIN through an ideal diode: LM74700-Q1 driving an N-channel MOSFET, wired as its datasheet's\\n"
           "typical application (source = ANODE = input, drain = CATHODE = VIN, EN tied to ANODE, 100 nF from VCAP to ANODE).\\n"
           "This lets the DC jack and USB-C be plugged in together, and blocks a reversed DC plug.\\n"
           "LIMITS TO RESPECT: the converters' absolute maximum input is 26 V. Use 20 V or less. The TVS (SMBJ20A) only limits\\n"
           "short spikes; it clamps well above 26 V at high current, so it does not make a 24 V supply safe.\\n"
           "Still to choose and check: the MOSFETs (40 V, a few milliohms), the fuse rating and the jack part number;\\n"
           "the inrush into the converters' input capacitors when USB-C power is applied; an over-voltage cut-off for field use.", 15, 15)
    a = Row(s, 25.4, 220.98)
    jack = s.place("Connector:Barrel_Jack", ref("J"), "DC in 12-19 V", 45.72, 96.52,
                   "Connector_BarrelJack:BarrelJack_CUI_PJ-063AH_Horizontal", passive=True,
                   fields={"Part": "CUI PJ-063AH footprint; confirm an 8 A rated jack"})
    s.nets(jack, {"1": "DC_JACK"})
    pwr(s, jack, {"2": "GND"})
    fuse = s.place("Device:Fuse", ref("F"), "8 A", 91.44, 93.98, "Fuse:Fuse_1206_3216Metric")
    s.nets(fuse, {"1": "DC_JACK", "2": "DC_IN"})
    ctl_id, ctl_fp = vendor_part("C2941042", power=r"^GND$")
    for i, (source, kind, label) in enumerate((("DC_IN", "local", "DC jack"), ("USBC1_VBUS", "global", "USB-C port 1"))):
        t = "OR%d_" % (i + 1)
        y = 91.44 + i * 63.5
        s.text(label, 147.32, y - 30.48, size=1.27)
        u = s.place(ctl_id, ref("U"), "LM74700-Q1", 190.5, y, ctl_fp, fields={"LCSC": "C2941042"})
        q = s.place("Transistor_FET:BSC028N06LS3", ref("Q"), "BSC028N06LS3", 266.7, y,
                    "Package_TO_SOT_SMD:TDSON-8-1",
                    fields={"Part": "60 V, 2.8 mOhm N-channel MOSFET, 5x6 mm; or an equivalent"})
        for part, pin in ((u, "ANODE"), (u, "EN"), (q, "S")):
            s.net(part, pin, source, kind=kind, shape="passive")
        glob(s, u, {"CATHODE": "VIN"}, "passive")
        glob(s, q, {"D": "VIN"}, "passive")
        s.nets(u, {"GATE": t + "GATE", "VCAP": t + "VCAP"})
        s.nets(q, {"G": t + "GATE"})
        pwr(s, u, {"GND": "GND"})
        a.cap("100nF 50V", t + "VCAP", source, FP_C0603, globals_=(source,) if kind == "global" else ())
        a.cap("100nF 50V", source, "GND", FP_C0603, globals_=(source,) if kind == "global" else ())
        a.gap()
    tvs = s.place("Device:D_TVS", ref("D"), "SMBJ20A", a.x, a.y, "Diode_SMD:D_SMB")
    glob(s, tvs, {"A1": "VIN"}, "passive")
    pwr(s, tvs, {"A2": "GND"})
    a.x += a.pitch * 3
    a.flag("VIN", "global")            # VIN is fed through the MOSFETs, which the rules check cannot see
    return s


# ---------------------------------------------------------------- sheet 25 --
def sheet_tpm():
    """TPM 2.0 on SPI1. Not from the reference; wired as the Infineon datasheet's typical schematic."""
    s = project.sheet("tpm", "TPM 2.0 security chip")
    s.text("NEW FOR THIS BOARD. Infineon SLB 9670 (the SLB 9672 was not found at LCSC), wired as the typical schematic in its\\n"
           "datasheet (vendor/lcsc_C539131): SPI, 100 nF at each VDD pin plus 1 uF, GPIO and PP left open.\\n"
           "Runs from VCC_3V3_S0, the same supply as the processor's GPIO bank 3 it talks to.\\n"
           "TPM reset follows the platform reset (RESET_L, 1.8 V) through a one-transistor level shifter, so software\\n"
           "cannot reset the TPM on its own: this is what measured boot relies on.\\n"
           "The interrupt pin is open-drain with no internal pull-up, hence the 10K.", 15, 15)
    chip_id, chip_fp = vendor_part("C539131", power=r"^VDD$|^GND$|^EP$")
    u = s.place(chip_id, ref("U"), "SLB 9670VQ2.0", 203.2, 119.38, chip_fp, fields={"LCSC": "C539131"})
    glob(s, u, {"VDD": "VCC_3V3_S0"}, "input")
    pwr(s, u, {"GND": "GND", "EP": "GND"})
    glob(s, u, {"~{CS}": "SPI1_CS0_TPM", "SCLK": "SPI1_CLK_TPM", "MOSI": "SPI1_MOSI_TPM", "MISO": "SPI1_MISO_TPM",
                "~{PIRQ}": "TPM_INT_L", "~{RST}": "TPM_RST_L"})
    s.nc(u, "GPIO", "PP", "NCI", "NC", "NCI/VDD", "NCI/GND")
    a = Row(s, 25.4, 220.98)
    a.cap("100nF", "VCC_3V3_S0", "GND", globals_=("VCC_3V3_S0",))
    a.cap("100nF", "VCC_3V3_S0", "GND", globals_=("VCC_3V3_S0",))
    a.cap("1uF", "VCC_3V3_S0", "GND", globals_=("VCC_3V3_S0",))
    a.res("10K", "VCC_3V3_S0", "TPM_INT_L", globals_=("VCC_3V3_S0", "TPM_INT_L"))
    a.res("10K", "VCC_3V3_S0", "SPI1_CS0_TPM", globals_=("VCC_3V3_S0", "SPI1_CS0_TPM"))
    a.res("10K", "VCC_3V3_S0", "TPM_RST_L", globals_=("VCC_3V3_S0", "TPM_RST_L"))
    # 1.8 V platform reset to the TPM's 3.3 V reset pin: one-transistor level shifter
    # (gate on 1.8 V, source on RESET_L, drain on TPM_RST_L with the pull-up above).
    q = s.place("Transistor_FET:BSS138", ref("Q"), "BSS138", 300.99, 119.38, "Package_TO_SOT_SMD:SOT-23")
    glob(s, q, {"G": "VCC_1V8_S3"}, "passive")
    glob(s, q, {"S": "RESET_L"}, "passive")
    glob(s, q, {"D": "TPM_RST_L"}, "passive")
    return s


# ------------------------------------------------------------------ verify --
def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def verify():
    root = os.path.join(HERE, project.name + ".kicad_sch")
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        # 1. Netlist cross-check: KiCad's own netlist must group pins exactly as intended.
        net_file = os.path.join(tmp, "netlist.net")
        r = run([KICAD_CLI, "sch", "export", "netlist", "--format", "kicadsexpr", "-o", net_file, root])
        if not os.path.exists(net_file):
            raise SystemExit("netlist export failed:\n" + r.stdout + r.stderr)
        tree = kg.parse(open(net_file, encoding="utf-8").read())
        kicad_net_of = {}
        for net in kg.find_all(kg.find(tree, "nets"), "net"):
            name = str(kg.find(net, "name")[1])
            for node in kg.find_all(net, "node"):
                kicad_net_of["%s.%s" % (kg.find(node, "ref")[1], kg.find(node, "pin")[1])] = name
        problems = []
        for name, nodes in sorted(project.nets.items()):
            nodes = [n for n in nodes if not n.startswith("#")]
            seen = set(kicad_net_of.get(n, "<missing>") for n in nodes)
            if len(seen) != 1:
                problems.append("net %s is split or missing in KiCad: %s" % (name, sorted(seen)))
        intended_of = {n: name for name, nodes in project.nets.items() for n in nodes}
        groups = {}
        for node, knet in kicad_net_of.items():
            if node in intended_of:
                groups.setdefault(knet, set()).add(intended_of[node])
        for knet, names in sorted(groups.items()):
            if len(names) != 1:
                problems.append("KiCad net %s merges intended nets %s" % (knet, sorted(names)))
        placed = sum(len(s.parts) for s in project.sheets)
        print("Netlist cross-check: %d parts, %d intended nets, %d pin connections"
              % (placed, len(project.nets), len(intended_of)))
        for p in problems:
            print("  FAIL  " + p)
        print("  ok    KiCad's netlist matches the intended connections" if not problems else "")
        ok = ok and not problems

        # 2. KiCad electrical rules check.
        erc_file = os.path.join(tmp, "erc.json")
        run([KICAD_CLI, "sch", "erc", "--format", "json", "--severity-all", "-o", erc_file, root])
        report = json.load(open(erc_file, encoding="utf-8"))
        counts = {}
        for sheet in report.get("sheets", []):
            for v in sheet.get("violations", []):
                key = (v["severity"], v["type"])
                counts.setdefault(key, []).append(v)
        total = sum(len(v) for v in counts.values())
        print("\nKiCad ERC: %d violation(s)" % total)
        for (sev, typ), items in sorted(counts.items()):
            print("  %-7s %-28s x%d" % (sev, typ, len(items)))
            for v in items[:60]:
                where = "; ".join(i.get("description", "") for i in v.get("items", []))
                print("            %s | %s" % (v.get("description", ""), where))
        ok = ok and not any(sev == "error" for sev, _ in counts)
    return ok


def build_all():
    """Create every sheet, in page order. Used by this script and by the board generator."""
    sheet_slots_pcie()
    sheet_slots_radio()
    sheet_soc_pcie()
    sheet_soc_usb()
    sheet_soc_power()
    sheet_ethernet(1)
    sheet_ethernet(2)
    sheet_pmic()
    sheet_core_regs()
    sheet_power_input()
    sheet_ddr(0)
    sheet_ddr(1)
    sheet_soc_system()
    sheet_soc_gpio(1)
    sheet_soc_gpio(3)
    sheet_pcie_clock()
    sheet_soc_display()
    sheet_usbc(1)
    sheet_usbc(2)
    sheet_usb_hub()
    sheet_emmc()
    sheet_peripherals()
    sheet_power_entry()
    sheet_tpm()


if __name__ == "__main__":
    build_all()
    project.write()
    print("Wrote %d sheets to %s" % (len(project.sheets) + 1, HERE))
    if "--verify" in sys.argv:
        sys.exit(0 if verify() else 1)
