#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""E-N0 parity: run the INTEGER streaming DNA (dna_fixed.py) inside the exact experiments the float DNA was
measured in, so the only difference is the engine.

  synthetic : behavioural_memory.main (E-BM1 / cold start), engine swapped
  iot23     : replay_bm_iot23.main (E-BM2b), engine swapped

The adapter turns each hourly observation (conns, peer set, bytes_out, suffix set, nx share) into the event
stream the device would see: one add_flow per distinct peer (all conns and bytes on the first), and one
add_dns per suffix (nx share as q_nx / 1000 queries). Data, guard policy and scoring code are unchanged.

Usage:
  python3 -I dna_fixed_eval.py synthetic --seeds 1,2,3,4,5 --blooms 1024 [--learn-hours 12]
  python3 -I dna_fixed_eval.py iot23 <iot23 dir> [--json out.json]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behavioural_memory as bm  # noqa: E402
import dna_fixed as fx  # noqa: E402


class _Mem(fx.AgingBloom):
    """AgingBloom that also answers `"ip:port" in mem` (the float experiments test strings)."""
    __slots__ = ("kind",)

    def __init__(self, kind):
        super().__init__()
        self.kind = kind

    def __contains__(self, s):
        return self.test(fx.peer_fp_from_str(s) if self.kind == 0 else fx.dns_fp_from_str(s))

    def nbytes(self):
        return 2 * fx.BLOOM_BITS // 8


class FixedAdapter(fx.DNAFixed):
    """The float DNA's interface (score / update / admit_persistent / cold / peers / dns), backed by DNAFixed.
    Scores are converted back from Q8 to float units, so thresholds and AUC code are shared."""

    def __init__(self, m_bits=None):
        super().__init__()
        self.peers, self.dns = _Mem(0), _Mem(1)

    def _agg(self, obs):
        conns, peers, bytes_out, sufs, nx = obs
        agg = fx.HourAgg()
        first = True
        for p in sorted(peers):
            agg.add_flow(self, fx.peer_fp_from_str(p), bytes_out if first else 0, conns if first else 0)
            first = False
        if first:
            agg.add_flow(self, None, bytes_out, conns)
        q = 1000 if sufs else 0
        nxq = int(round(nx * q))
        for j, s in enumerate(sorted(sufs)):
            agg.add_dns(self, fx.dns_fp_from_str(s), False)
        agg.q_total, agg.q_nx = q, nxq
        return agg

    def nbytes(self):
        return fx.DNAFixed.nbytes()

    def score(self, hr, obs):
        s, parts = super().score(hr, self._agg(obs))
        return s / 256.0, {k: v / 256.0 for k, v in parts.items()}

    def update(self, hr, obs, admit_items=True):
        super().update(hr, self._agg(obs), admit_items)

    def admit_persistent(self, peers, suffixes, k=None):
        agg = fx.HourAgg()
        agg.novel_list = ([(0, fx.peer_fp_from_str(p)) for p in sorted(peers)] +
                          [(1, fx.dns_fp_from_str(s)) for s in sorted(suffixes)])[:fx.NOVEL_LIST]
        super().admit_persistent(agg)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("synthetic", "iot23"):
        print(__doc__)
        sys.exit(2)
    which = sys.argv[1]
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    bm.DNA = FixedAdapter
    print("ENGINE = integer streaming DNA (dna_fixed.py), %d B/device incl. hour aggregator" % fx.DNAFixed.nbytes())
    if which == "synthetic":
        bm.main()
    else:
        import replay_bm_iot23 as rb
        rb.bm.DNA = FixedAdapter
        rb.main()


if __name__ == "__main__":
    main()
