"""Naming rule for the LPDDR4X signal nets (checked against the reference by verify_ddr.py)."""
import re


def dram_net(pin, channel, half):
    """Net carried by a memory-chip signal pin; half is the processor's letter (A/B or C/D)."""
    m = re.match(r"(DQS(\d)_([tc])|DQ(\d+)|DMI(\d)|CA(\d)|CK_([tc])|CKE(\d)|CS(\d))_[ab]$", pin)
    if not m:
        return None
    base = "DDR_CH%d_" % channel
    if m.group(2) is not None:
        return base + "DQS%s%s_%s" % (m.group(2), "P" if m.group(3) == "t" else "N", half)
    if m.group(4) is not None:
        return base + "DQ%s_%s" % (m.group(4), half)
    if m.group(5) is not None:
        return base + "DM%s_%s" % (m.group(5), half)
    if m.group(6) is not None:
        return base + "A%s_%s" % (m.group(6), half)
    if m.group(7) is not None:
        return base + "CLK%s_%s" % ("P" if m.group(7) == "t" else "N", half)
    if m.group(8) is not None:
        return base + "LP4/4X_CKE%s_%s" % (m.group(8), half)
    return base + "LP4/4X_CS%s_%s" % (m.group(9), half)
