# 22: CTU-13 dev/test split for Neuro (pre-registration, 2026-11-21)

Frozen **before** any CTU-13 window was exported or looked at by Neuro. The intel-data session computed the split,
and Neuro recomputed and confirmed it.

## Rule

- It is the IoT-23 function: `SPLIT_RULES["neuro-sha256-mod3"]` in the intel-data `windows.py`.
- **dev** iff `int(sha256(name), 16) % 3 == 0`, otherwise **test**.
- `name` is the capture directory exactly as it appears in the mirror: `CTU-13.Dataset-<capture>`.

The intel-data session posted per-split flow counts before this freeze. To avoid choosing a split by its outcome,
the mirror names are kept. Switching to Stratosphere's canonical `CTU-Malware-Capture-Botnet-<n>` names would
hash differently and is ruled out.

| Scenario | Mirror directory | mod 3 | Split | Botnet / Normal flows |
|---|---|---|---|---|
| 1 | CTU-13.Dataset-42 | 0 | **dev** | 40,961 / 30,387 |
| 2 | CTU-13.Dataset-43 | 2 | test | 20,941 / 9,120 |
| 3 | CTU-13.Dataset-44 | 1 | test | 26,822 / 116,887 |
| 4 | CTU-13.Dataset-45 | 1 | test | 2,580 / 25,268 |
| 5 | CTU-13.Dataset-46 | 0 | **dev** | 901 / 4,679 |
| 6 | CTU-13.Dataset-47 | 2 | test | 4,630 / 7,494 |
| 7 | CTU-13.Dataset-48 | 2 | test | 63 / 1,677 |
| 8 | CTU-13.Dataset-49 | 0 | **dev** | 6,127 / 72,822 |
| 9 | CTU-13.Dataset-50 | 1 | test | 184,987 / 29,967 |
| 10 | CTU-13.Dataset-51 | 1 | test (missing: no binetflow on the mirror) | — |
| 11 | CTU-13.Dataset-52 | 1 | test | 8,164 / 2,718 |
| 12 | CTU-13.Dataset-53 | 1 | test | 2,168 / 7,628 |
| 13 | CTU-13.Dataset-54 | 2 | test | 40,003 / 31,939 |

**Dev** has 3 scenarios and about 48k botnet flows. **Test** has 9 scenarios and about 290k. If scenario 10
appears later, it follows the rule (test). There is no re-split.

## Use

**Windows.**
- Host-hour windows, in the IoT-23 window schema, only for hosts with Botnet or Normal labels.
- Background flows that touch such a host stay in its window as unlabelled context, with a per-window count.
  They are never treated as benign.
- The window label comes from labelled flows only.

**Access.**
- Neuro receives the **dev** split only, as an immutable build with a manifest SHA-256 (to be pinned here on
  export).
- The test split is sealed in the intel-data registry (`sealed.json`, scope `split:test@neuro-sha256-mod3`).

**Purpose.** T0 v4 training and dev material: real, non-IoT botnet behaviour (Neris, Rbot, Virut, Murlo and
others), complementing IoT-23.

**Not for blind evaluation.** CTU-13 is in the intel-data commercial build, so no CTU-13 scenario is used in
Neuro's blind v3.
