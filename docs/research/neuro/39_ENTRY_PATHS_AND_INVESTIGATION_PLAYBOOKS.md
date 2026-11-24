# 39: Entry paths and investigation playbooks from CVE and MITRE data (design, 2026-11-23)

**Status:** design only. **Not** a pre-registration. Nothing is downloaded, trained or measured here. Each phase
below that trains or evaluates gets its own pre-registration first.

**Origin.** The operator proposed using every known CVE plus the MITRE framework, so that Neuro learns how an
attacker gets in and therefore how to investigate: look, close in, and trace every entrance.

## 1. What this is for, and what it is not

**For: the explainer's investigation skill (L2).** Given a window, Neuro should:
- name the likely entry technique for **this device class**;
- say what the network can and cannot show about it;
- choose the **next step**: which flows, which DNS, which reputation lookup;
- say what would confirm it and what would clear it.

The explainer already has a `tool` task (`lookup_reputation`, `query_flows`, `query_dns`, `propose_policy_change`).
This track deepens it into multi-step investigation.

**Not for:**
- **Detection.** A CVE record does not describe what an exploit looks like on the wire. Detection stays with S1
  and M4 (docs 31, 35, 37).
- **Memorising CVEs.** A model that recites CVE ids will invent some. The hallucination bar (≤ 0.02) would catch
  that, and it would erode trust in every answer.
- **Exploitation.** No exploit code, no PoC collections (`trickest-cve` is excluded), no step-by-step attack
  instructions. Playbooks stay at ATT&CK technique level, which is defensive and already public.
- **Enforcement.** Output stays advisory. Neuro may *propose* an investigation or a policy change for the owner. It
  never acts on the kernel (doc 30; "LLM output never directly modifies kernel enforcement").

## 2. Data (intel-data registry, 2026-11-23)

| Source (registry id) | What it gives | Licence / training use | Role |
|---|---|---|---|
| `cisa-kev` | about 1,800 CVEs with confirmed in-the-wild exploitation | OPEN / yes | which entries attackers actually use; weights the entry graph |
| `cve-list-v5` | every CVE record: product, CWE, description | OPEN / yes | product and weakness of each KEV entry; **lookup only** at inference |
| `nist-nvd-api2`, `nvd-cpe-dictionary` | CVSS attack vector (network or local), CPE product names | OPEN / yes | keep only network-reachable entries; map products to device classes |
| `mitre-cwe` → `mitre-capec` → `mitre-attack-stix` | weakness → attack pattern → technique, plus each technique's data sources | OPEN / yes | the chain from a bug to a technique, and what can observe it |
| `mitre-d3fend` | defensive techniques mapped to ATT&CK | OPEN / yes | what to do once a technique is suspected: the "close in" step |
| CTID CVE→ATT&CK mappings | curated KEV-to-technique mappings | **not in the registry yet** | intel-data registers it and decides its licence first |

**Excluded:**
- `first-epss`: licence UNKNOWN;
- `mitre-emb3d`: RESTRICTED;
- `trickest-cve`: PoC references, against §1;
- `hf-all-cve-records`: third-party chat rewrites of CVEs; the primary sources are used instead.

**Size.** Probably under 3 GB in total; intel-data states it in the request. Downloads need the operator's approval
in intel-data's session, and each use is checked against the registry first (licence rule).

## 3. What gets built

### 3.1 Entry-path graph (`data/entry-paths.json`, deterministic)

For each device class N0 already distinguishes (router, NAS, IP camera, smart TV, printer, IoT hub, laptop, and so
on):
1. **Join.** KEV entry → CVE record → CPE product → device class (a hand-reviewed product→class table), keeping
   only CVSS attack vector = network or adjacent.
2. **Chain.** CVE → CWE → CAPEC → ATT&CK technique, and where CTID maps the CVE directly, its mapping wins.
3. **Weight.** How many KEV entries reach each (device class, technique), and how recently they were added.
4. **Observability.** Each technique's ATT&CK data components, reduced to what a gateway sees: network traffic
   flow, network traffic content (headers only), DNS, connection creation. Techniques the gateway cannot see are
   kept and marked **invisible here**, so the explainer can say so honestly.

The output is reviewed by hand before use, and checked into the repo with its build script and source hashes. It
is small and auditable: dozens of techniques per class, not 430,000 CVEs.

### 3.2 Investigation playbooks (`data/playbooks/`, one per technique)

For each technique in the graph:
- **seen on the wire as** (gateway-observable signs, in DNA and evidence-card terms);
- **next steps** (ordered tool calls);
- **confirms** / **clears** (what result moves the verdict either way);
- **close in** (D3FEND-mapped defensive actions, all as *proposals*: isolate, restrict to internet-only, block a
  peer);
- **cannot see** (what the gateway cannot observe, such as host-side execution after a successful exploit).

Playbooks are written by hand from the graph and ATT&CK text, and reviewed. They are the training curriculum,
**not** a runtime rule set.

### 3.3 Training cases (T0 family `f_investigate`)

From the playbooks, generated like the T0 v3 families:
- **Next step:** a window with one observed sign; the gold is the playbook's next tool call, on the right entity.
- **Multi-step:** the context includes the result of a first query; the gold is the next step or the verdict.
- **Clears:** the follow-up shows a benign explanation; the gold verdict is benign or insufficient, so the
  playbooks also teach *stopping*, which keeps doc 36's over-hedging lesson in view.
- **Invisible:** the technique cannot be seen from the gateway; the gold says so and proposes the owner check the
  device.

**Gold never contains a CVE id.**

### 3.4 CVE facts only at inference (`lookup_exposure`)

A new **read-only** tool for the explainer: `lookup_exposure(entity)`. It returns the KEV entries for the device's
product when N0 or the owner knows the product, otherwise its class.

- Answers cite what the tool returned. The model never states a CVE id it did not receive.
- This is the licence rule's pattern (feed values only at inference) applied to vulnerability facts.
- **The limit, stated in every answer that uses it:** firmware versions are rarely known at the gateway, so a match
  means "devices like this are often hit by X", not "this device is vulnerable".

## 4. How it would be judged (outline; fixed in the phase pre-registrations)

- **Fresh blind set of investigation cases.** An isolated author, as for blind v3–v7, from a brief that never sees
  the playbooks. Subsets: next step, multi-step, clears, invisible, plus decoys where no investigation is warranted.
- **Metrics:**
  - next-step accuracy (tool + entity);
  - stop accuracy (no tool when none is warranted);
  - **zero CVE ids not returned by `lookup_exposure`** (a hard gate);
  - hallucination ≤ 0.02;
  - canary-safe, unchanged.
- **Comparators:** the base model and the current candidate (ftFg, or ftIg if doc 38 passes), both with the same
  tools.
- **No regression:** the doc 36 / 38 conditions on the existing subsets still hold.

## 5. Phases

| Phase | What | Needs |
|---|---|---|
| P0 | intel-data registers the CTID mappings and checks each source's licence for this use | intel-data |
| P1 | download (about 3 GB or less), entry-path graph and its build script, hand review | **operator approval** in intel-data's session |
| P2 | playbooks for the top techniques per device class; review | Neuro; operator review welcome |
| P3 | `lookup_exposure` tool and its cases; pre-registration (doc 40); blind investigation set | Neuro |
| P4 | train, select on a fresh dev set, one blind look | after doc 38 has finished, so the two experiments don't share a training run |

**Status (2026-11-24).**
- **P0 done:** CTID registered (#1537).
- **P1 done:** entry-path graph (#1539, `data/entry-paths-review.md`): entry is T1190 or T1203; the gateway's value is
  the follow-on behaviour.
- **P2 done:** 16 playbooks (`data/playbooks.md`, built and validated by `playbooks.py`):
  - 4 entry: T1190, T1133, T1110, T1203;
  - 11 follow-on: tool download, C2, DGA, web shell, mining, scanning, flooding, exfiltration, tunnelling,
    lateral movement, proxyware;
  - 1 not observable (credential dumping), so the explainer says so instead of guessing.

  Every ATT&CK id, D3FEND id and label, tool and DNA feature is checked against intel-data's raw files; no CVE id
  appears.
- **Next: P3.** `lookup_exposure`, the investigation cases, and their own pre-registration.

## 6. Risks

1. **Coverage bias.** KEV over-represents enterprise products (VPNs, firewalls, mail servers). Home-device classes
   have fewer entries, so their weights rest on few examples. The graph shows counts, so thin classes are visible.
2. **Template learning.** As doc 38 §7.1: generated cases can teach templates. The isolated blind author is the
   check.
3. **Over-investigation.** A model trained on playbooks may call tools on every window. The "clears" and "decoy"
   subsets, plus the stop-accuracy metric, guard against it.
4. **Dual use.** Kept at technique level with defensive framing. Exploit material is excluded at the source (§2).
