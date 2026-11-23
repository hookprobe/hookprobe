#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 37 amendment D: UNSW 12-homes "ML instance" CSV -> the YAF/IPFIX biflow CSV that ipfix_to_dna.py reads.
Pure column plumbing; no row is dropped or filtered here, and no model is involved.

The homes export (seen at intake, header lines and plumbing-column summaries only) is not IE-named:
  start (datetime, ms), duration (s; capped at 1800 = YAF's active timeout), srcMac, destMac, srcIP, destIP, ipProto,
  srcPort, destPort, outPacketCount, outByteCount, inPacketCount, inByteCount, ..., deviceInitiated (0/1), device.
Intake checks on home1 (200,000 rows): src is ALWAYS the initiator (deviceInitiated=1 <=> srcMac is the device's MAC;
0 <=> destMac is), and every device's MAC is on every one of its rows. out/in counts are from the DEVICE's side.

Mapping (one output row per input row):
  flowStartMilliseconds = start as UTC epoch ms (the export gives no zone; only hour boundaries matter, and a whole-hour
                          offset does not move them)
  flowEndMilliseconds   = start + duration * 1000
  sourceIPv4Address / destinationIPv4Address / ports / protocolIdentifier = srcIP / destIP / srcPort / destPort / ipProto
  octetTotalCount, packetTotalCount (initiator)  = out* if deviceInitiated else in*
  reverseOctetTotalCount, reversePacketTotalCount = in*  if deviceInitiated else out*
  deviceMac     = srcMac if deviceInitiated else destMac   (device identity, doc 37 §3: a per-row MAC is used)
  deviceAddress = srcIP  if deviceInitiated else destIP
No reverseUnionTCPFlags column exists, so conn_state REJ cannot occur (as in the frozen path; ipfix_to_dna.py notes it).
Usage: homes_ml_to_yaf.py <out dir> <homeN.csv>...   then  ipfix_to_dna.py ... --device-cols deviceMac,deviceAddress
"""
import csv, datetime as dt, os, sys

OUT = ["deviceMac", "deviceAddress", "flowStartMilliseconds", "flowEndMilliseconds", "sourceIPv4Address",
       "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "octetTotalCount",
       "reverseOctetTotalCount", "packetTotalCount", "reversePacketTotalCount"]
UTC = dt.timezone.utc


def conv(src, dst):
    n = 0
    with open(src, newline="", encoding="utf-8") as f, open(dst, "w", newline="") as g:
        r, w = csv.DictReader(f), csv.writer(g)
        w.writerow(OUT)
        for row in r:
            dev = row["deviceInitiated"].strip() == "1"
            t0 = dt.datetime.fromisoformat(row["start"]).replace(tzinfo=UTC).timestamp() * 1000.0
            t1 = t0 + float(row["duration"] or 0) * 1000.0
            ob, op, ib, ip = row["outByteCount"], row["outPacketCount"], row["inByteCount"], row["inPacketCount"]
            w.writerow([(row["srcMac"] if dev else row["destMac"]).lower(), row["srcIP"] if dev else row["destIP"],
                        "%.3f" % t0, "%.3f" % t1, row["srcIP"], row["destIP"], row["srcPort"] or 0, row["destPort"] or 0,
                        row["ipProto"], ob if dev else ib, ib if dev else ob, op if dev else ip, ip if dev else op])
            n += 1
    return n


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for p in sys.argv[2:]:
        n = conv(p, os.path.join(out, os.path.basename(p)))
        print("%s: %d rows" % (os.path.basename(p), n), flush=True)


if __name__ == "__main__":
    main()
