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

**Pinned dev export (2026-11-21, intel-data #1435).** `windows-d1bc3ad9dae8`. Neuro verified every hash below, and
all files are read-only. The 9 test scenarios appear in the manifest only as "skipped: split test not requested".

| | SHA-256 | Windows | Events (background) | Labelled hosts |
|---|---|---|---|---|
| `manifest.json` | `6cdcaaba60452b8fb1f18e17baa72e038a774e3690717ca2845144316eebe9bc` | | | |
| `CTU-13.Dataset-42.jsonl` | `b751eda2b0c765f4dd2974b03feb54dc01847272c46f166a30034c75b8d83ce6` | 47 | 824,913 (753,685) | 11 |
| `CTU-13.Dataset-46.jsonl` | `945484f97a1b84bc97e34a1199fcb944a846675ed457201725bedd42ab3e872d` | 17 | 37,100 (31,531) | 12 |
| `CTU-13.Dataset-49.jsonl` | `1cb57d552448bb3cfd0cb8a32eb0c9995c5c2661ddb653feb1d3de0623899cbd` | 109 | 708,654 (629,887) | 9 |

**Host rule as exported.**
- A window host originates `From-` or undirected `Normal-` flows.
- A `To-` label names a verified external server, so it never makes a host. Its flows join the window of
  whichever end is a host; otherwise they are dropped and counted (120 / 11 / 182 per scenario above).

**Known format differences from IoT-23.**
- `state` is null: Argus State is not mapped, so rep_cards' rst% reads 0.
- `hour_utc` is the capture clock and not verified UTC.
- Background events carry `label` null.

**Lookup tables (for a CONTEXT line, not training text).** `lookup-2209c34c15c7`, manifest
`b4f8f54ea0dff738c46407edb1dad43f711a8b5d486f095e30aa601bc7b93412`. Record facts only:
- `cve.jsonl`: 418,514 rows. Fields: CWE, CVSS band, vendor, product, and KEV as of the 2026-11-18 snapshot.
- `attack.jsonl`: 935 techniques (enterprise, mobile and ICS), each with name and tactics.

**Purpose.** T0 v4 training and dev material: real, non-IoT botnet behaviour (Neris, Rbot, Virut, Murlo and
others), complementing IoT-23.

**Not for blind evaluation.** CTU-13 is in the intel-data commercial build, so no CTU-13 scenario is used in
Neuro's blind v3.
