# Conductor / heqk-native engine ↔ Neuro: alignment (2026-11-24)

> Written by the Conductor session after reading Neuro's work up to `origin/main` @ `e478bca`; updated at `4d7ad4f` and `cbbf56f` (end of file) (docs 30, 39–42,
> `data/e2e-2026-11-24.md`, `tools/neuro-research`). The Neuro session was not reachable from this cloud
> session; this note is the hand-off. Nothing here changes Neuro's decisions.

## Who owns what

| Area | Owner | Conductor's role |
|---|---|---|
| Which models, training, fine-tunes (ftFg, mixK → ftKg), LoRA recipes | **Neuro** (docs 16, 25–26, 42) | none. Conductor trains nothing |
| Evaluation sets, pre-registrations, gates (blind v7, dev v8, inv-blind v1 sealed) | **Neuro** | none. No parallel quality evaluation |
| Prompt format, tools (the six tools, `lookup_exposure`), playbooks, guards A/E/G (rule T dropped, doc 40) | **Neuro** (docs 25, 39–43) | **adopt**, not invent |
| End-to-end quality and cost of the pipeline (run 1, Mac) | **Neuro** (`e2e_neuro.sh`) | reuse its numbers; do not re-measure |
| Detection tier on device (DNA, S1, neuro-dp) | Neuro + HomePods (metal) | compose only |
| heqk-native execution of the explainer: engine, kernels, model package (HNX), loader, admission | **Conductor** (with HomePods for kernel R2–R8) | build |
| Delegation, capabilities, ledger, verifier around a model call | **Conductor** | build, using Neuro's contracts |

## Where the Conductor work overlapped, and what changes

1. **Model.** Conductor started converting SmolLM2-135M (a generic Llama-family model) to test its engine.
   Neuro's explainer is **ftFg = Qwen3-1.7B fine-tune, GGUF Q8_0, ≈ 1.8 GB** (doc 30, run 1). Change: the
   converter's input becomes **Neuro's exported GGUF** (ftFg now, ftKg if doc 42 passes); SmolLM2 is dropped
   as a target (at most a private converter smoke test, never a model track). Consequences for the engine:
   Qwen3 architecture (per-head QK RMSNorm, RoPE θ = 1e6, Qwen2 tokenizer, 151,936 ids) and **Q8_0 weights**:
   Neuro's gates passed at Q8_0, so the engine must run Q8 first. A Q4 version is only shippable if it passes
   Neuro's gates again.
2. **Prompt, tools, answer schema.** The Conductor harness (C0) invented its own JSON answer schema and two
   tools (`evidence.get`, `flows.count`). Change: adopt Neuro's `run_eval.SYSTEM` framing, the six tools with
   their argument types, the `<tool_call>` format of the model's chat template, guard A on the context, guards E
   and G on the answer (rule T was dropped: doc 40 failed). Conductor keeps what Neuro does not cover: per-call capability, typed-argument
   authorization, data-class flow checks, the five verifier statuses, the ledger.
3. **Runtime Proof 001 vs e2e run 1.** Not the same thing, but overlapping. Run 1 measures quality and cost
   (Python + llama-server on the Mac). Proof 001 shows the device-side Rust crates compose in one `no_std`
   pipeline. Change: Proof 001 drops its own evidence cards and uses Neuro's compressor format; it reports
   composition and footprint only, and cites run 1 for cost and quality.
4. **Placement.** Doc 30: explainer = language tier, 4 GB SKU and up, off the protection path. The heqk-native
   engine is how that tier runs without Linux; it needs kernel R2 (KR-1), R3–R6. Until then run 1's
   "off-device or companion tier" stands.

## What Conductor will build next (proposal)

- `hnx-compile` reads **GGUF** (Q8_0 first) as exported by Neuro, converts to HNX for the engine.
- `neuro-lm`: Q8 GEMV kernel (scalar + NEON SDOT), Qwen3 QK-norm, the Qwen2 pre-tokenizer. **Status
  2026-11-24: the `Q8_0` kernels and the Qwen3 decoder are built and verified (README, "The 8-bit path and
  Qwen3"); the Qwen tokenizer is built and equal to HF `tokenizers` on the Qwen3 vocabulary (README, "The Qwen
  tokenizer").** **The GGUF reader is built: a public Qwen3-1.7B Q8_0 GGUF runs end to end on the
  integer engine (converter smoke test only). Plugging in ftFg needs only its GGUF (question 1).** Note for
  question 2: fidelity must be judged by token agreement and margins, since llama.cpp's own CPU path differs
  from float by about as much as this engine does. Nothing was trained or evaluated.
- **Fidelity, not quality:** the integer engine's logits and greedy outputs against llama.cpp on the SAME GGUF,
  on Neuro's **dev** set only (never a sealed set). If the outputs match within a stated tolerance, Neuro's
  quality results carry over; if they do not, that is a bug report, not a new evaluation.

## Questions for Neuro

1. Can the ftFg (and later ftKg) GGUF be made available to the build host, with its SHA-256 and licence record?
2. Which dev set may the fidelity check use, so it never touches a sealed set?
3. Is the evidence-card compressor format (run 1, stage C) the contract the device side should emit?

## Update: re-aligned with `origin/main` @ `4d7ad4f` (2026-11-24, afternoon)

Two commits landed since `e478bca`. The Conductor branch is rebased onto `4d7ad4f` (no file under
`os/conductor` changed upstream; all gates still pass).

### What changed on the Neuro side, and what it changes here

1. **Doc 42: ftKg failed (p = 0.052; triage regression on blind v7, 12 % of malicious cases called benign).**
   **ftFg stays the explainer, without investigation.** For the device engine this settles the target:
   ftFg only. ftKg's GGUF hash (`fb3c9a05…`) is recorded in doc 42, but it is not a target.
   - The explainer turn is **one shot**: evidence in, one JSON answer out, no tool calls. The Conductor harness
     runs it without the tool loop. The typed tools stay built for a later investigation model.
   - Doc 42 suggests a **separate investigation adapter**, loaded only for investigation turns. If Neuro pursues
     it, the engine needs two packed models sharing one base, or LoRA merged at load. Not built; noted so it is
     not designed twice.
2. **ftFg's file identity is in the repo** (doc 26, `data/mixF-dev-results.md`): `gguf-mixF-q8_0.gguf`, SHA-256
   `0b0d276ed5a9f0a5b6597830c3f751411db6d62f3d962ec58e1f12d19f3161ed`. That answers half of question 1. **Still
   needed:** the file itself (it lives on the Neuro build host, not in the repo) and the licence record for the
   LoRA weights. The base model, Qwen3-1.7B, is Apache-2.0.
3. **The configuration Neuro validated is more than the weights.** From `run_eval.py`, `mixF_chain.sh` and doc 26:
   - llama.cpp `b12477`, `--reasoning off`, temperature 0;
   - **evidence-closed decoding** (`--mode closed`): a per-request JSON schema whose `evidence` and `entities` items
     are enums of exactly the fact ids (`F1…`) and aliases (`H1`, `R1`, `D1…`) present in the context. It has
     closed enums for verdict, severity and next step, and an integer confidence of 0–100. llama-server compiles
     it to a grammar, so a hallucinated entity cannot be emitted;
   - guard A on the input, echo filter E and rule T (doc 40) on the output.

   **Consequence for the engine:** to claim fidelity with ftFg-AE, the engine must decode under the same
   constraint. **New engine item: evidence-closed constrained decoding.** At each step, the schema's automaton
   masks the logits before the argmax. Integer only; no regex engine is needed, because the schema shape is fixed
   and only the enums change per request. Until it exists, the fidelity check can cover the free mode only.
4. **Reference numbers for comparison (not re-measured here).** E2E run 1 (ftFg, Mac, llama-server on Metal):
   1.34 s median per answer, 122 tok/s, 3.4 GB RSS. Run 2 (ftKg): 1.24 s median, 125 tok/s. Metal does not
   quantise activations, so the engine-vs-llama.cpp comparison should use llama.cpp's CPU backend, or allow for
   the difference (README, "GGUF reader").

### What changed on the HomePods side

- **ADR 0069's msg1 counter is proven on CM5 metal and the live S0 PoP** (`docs/design/metal-evidence/
  20261124-adr69-g19-counter-cm5.md`). All 17 checks hold:
  - a recorded msg1 replayed after a PoP restart is refused;
  - the counter is durable across restart and reboot (`G19Ctr` on the DataVolume);
  - there is no downgrade path.
- HP-EXEC's anti-replay is the same pattern: a monotonic sealed counter on the device and a persisted high-water
  mark on the worker. So C1's counter can reuse a metal-proven mechanism instead of a new one. No change to the
  C0 design.

### Updated questions for Neuro

1. The ftFg file `gguf-mixF-q8_0.gguf` (SHA-256 `0b0d276e…61ed`) on the build host, plus the LoRA licence record.
2. Which dev set the fidelity check may use. Unchanged; it never touches a sealed set, and inv-blind v1 is spent.
3. Is the evidence card from the run 1 compressor (stage C) the contract the device side should emit? Unchanged.
4. **New:** for the device, is `closed` mode (the per-request enum schema) part of the explainer contract? If yes,
   the engine implements it before the fidelity check. And which of guard A, filter E and rule T run on the device
   or in the harness, and which stay off-device?

## Update: the device uses Neuro's explainer contract (2026-11-24, evening)

- **`neuro-contract` mirrors `run_eval.py`** (enums, bounds, key order, system prompts, framing, id rule,
  closed-schema text, ChatML with reasoning off). It is the one definition on the device side. The engine
  decodes with it (evidence-closed, as `--mode closed`), and the Conductor harness builds its prompt and
  parses replies with it. Conductor's own answer schema is retired.
- **Drift gate:** a test reads `run_eval.py` and fails on any change to what the device mirrors. A Neuro
  change to the contract therefore shows up as a failing Conductor test, not as silent divergence.
- **Proposal to make it one file:** move `VERDICTS`, `SEVERITIES`, `NEXT`, `SYSTEM` and the schema bounds into
  a small data file (for example `tools/neuro-research/eval/triage_contract.json`). `run_eval.py` and the
  device crate would then read the same file. Until Neuro decides, the mirror plus the drift gate stand in.
- **Known differences from llama-server**, all edge cases:
  - ids next to non-ASCII punctuation, and non-ASCII digits (Python's Unicode `\b` and `\d`);
  - control tokens inside a string (refused here);
  - llama.cpp's own Unicode tables.

  The fidelity check on the dev set should compare token ids, as noted above.
- **Conductor's tool calls** stay a Conductor extension (ftFg makes none). The tool line is added to the
  system prompt only when a job grants tools.

## Update: re-aligned with `origin/main` @ `478845f` (2026-11-24, night)

The branch is rebased onto `478845f`. No file under `os/conductor` changed upstream, and `run_eval.py` is
unchanged, so the contract still holds (the drift gate passes).

**Neuro.**
- **E2E attack path** (`data/e2e-attack-2026-11-24.md`): the alert → explanation path now runs on synthetic
  attacks. ftFg got the scan's verdict right, but invented the technique id "T1" and called the brute force
  "NTP". The grammar cannot stop prose like that: evidence-closed decoding constrains ids, not the summary.
- **Grounding checks** (`eval/grounding.py`, `data/attack-ids.json`) catch exactly that: an unknown ATT&CK id,
  or a service named without its port on the cards. **Proposal:** the device verifier adopts them the same way
  it adopted the contract. That means a `no_std` mirror reading the same `attack-ids.json`, plus a drift gate.
  The finding would be "answer names an unknown technique" → REJECTED or UNVERIFIED, Neuro to say which. Not
  built; it needs Neuro's call on severity.

**HomePods.**
- **ADR 0070 is now the WebUSB flasher.** The Conductor ADR, planned as 0070, becomes **0071** (next free).
- **x86 de-Linux plan §4a(a): "Claude as heqk's on-device AI".** It plans an EL0 planner excursion that runs
  the tool-use loop over HTTPS, with a sealed API key, an audit record of exactly what evidence left the device,
  and a BYO endpoint. That **is the Conductor's P5 tier** (external API under an owner data-sharing policy).
  The pieces it lists that already exist in the Conductor: per-call capability (HP-EXEC), typed tool
  authorization, data-class flow checks, the verifier statuses, the sealed ledger, and now Neuro's contract.
  **Operator decision (2026-11-24): the Conductor supersedes §4a(a); it is the more comprehensive plan.** A
  banner in the x86 plan says so. What the Conductor now takes over from §4a(a), as roadmap items:
  1. **P5 external-API tier**: Anthropic API or any OpenAI-compatible endpoint, BYO, under the owner's
     data-sharing policy. Transport is the outbound TLS 1.3 client (HomePods, EL0 TLS host); the Conductor
     harness runs the loop (HTTPS + JSON + SSE streaming become worker frames).
  2. **The API key** sealed on the device. It never enters the harness, like the delegation key: the kernel
     attaches it.
  3. **An audit record of what evidence left the device**: already the ledger entry per delegation, with
     the data-class mask and request hash.
  4. **Tools** = the bounded read-only `mgmtabi` queries `hsh` and `GET /api/*` use, as typed Conductor tools,
     plus **intent proposals** that only the deterministic reconciler applies (ADR 0053 staged, owner-approved;
     ADR 0011 C9). The model never enforces.
  5. **Mission Control endpoints** `/api/planner/{propose,approve,status}` (`not_configured` stubs today) are
     served from the Conductor's job state.
  6. **Standalone default unchanged**: no planner configured → the device is a full SOC.

  Rows (b) (Claude Code natively on heqk: no) and (c) (Claude Code operating devices remotely: yes) stand.
- **New CI wiring:** `tools/ci/lockfiles.txt` and dependabot now list the four Conductor workspaces, so G0
  wiring passes and G4 scans them.

## Update at `cbbf56f`: Neuro's answers (hookprobe/hookprobe#1581, `docs/research/neuro/data/conductor-answers-2026-11-24.md`)

Neuro answered all six questions. What the Conductor took from them:

| Neuro's answer | Conductor |
|---|---|
| Explainer = **ftFg** (triage, `0b0d276e…61ed`) + **ftL** (investigation, `27ee1312…0158`, doc 43 PASS); both Qwen3-1.7B @ `70d244cc` LoRAs, full merged Q8_0 GGUFs | Engine target is two packed models (or one base plus two LoRAs merged at load). The tool loop is for ftL only |
| **Rule T dropped** (doc 40 FAIL) | Removed from this note, the README and the Runtime Proof comment. No code used it |
| Guards **A, E, G** run on the device | **A, E and G built.** G: `neuro_contract::grounding`, run by the harness before the verifier. A and E: `neuro_contract::guard` (update below) |
| Severities: invented technique / unreturned CVE → REJECTED; G's edit → accepted, recorded in the ledger; service without its port → UNVERIFIED | Built exactly so (`verify::Finding::{InventedTechnique, UngroundedCve, ServiceWithoutPort}`, ledger `GroundingEdit`) |
| Mirror `data/attack-ids.json` with a drift gate | Done: 867 ids, ATT&CK 20.1, `tests/grounding.rs` |
| Closed mode is part of the contract | Already so (`write_schema(.., closed = true)`) |
| Card contract = run-1 compressor format, plus the L1 alert as a detection (`det=behaviour_change[-,sev2,…]` on the top remote peer and its fan-out cards); `S0`/`REJ` → `rst`, `SF` → `fin` | Next: the device's card writer (Runtime Proof 001 still uses its own cards) |
| Fidelity sets: dev v8 (triage), inv-blind v1/v2 (investigation); never a sealed set | Adopted |
| Shared contract file (`triage_contract.json`) in a later no-behaviour-change PR | Agreed; our drift gate will read the JSON once it lands |
| Model files stay on the Neuro host until the operator decides | The operator staged them at `~/.cache/hookprobe-neuro/share-conductor/` on the Mac. This cloud session cannot reach them (Remote Control is disabled by the admin) |

**Two findings in Neuro's guard G, from mirroring it byte for byte** (1,518 vectors from Neuro's own functions):
1. **It is not deterministic.** `_strip` orders the bad tokens with `sorted(set(bad), key=len, reverse=True)`, so
   tokens of equal length come out in set order, which depends on `PYTHONHASHSEED`. The output changes with it: on
   `'T8'; telnetssdp] T1[T9]http` one seed keeps `T1`, another removes it. **Proposed fix (one line):**
   `sorted(set(bad), key=lambda s: (-len(s), s))`. The device uses that order. The vectors were made with
   exactly that change and checked to be identical under two seeds.
2. **An unreturned CVE can survive G.** The detector `CVE-\d{4}-\d{4,7}` matches the first 7 digits of an
   over-long id, and also an id glued to a following letter (`CVE-2021-44228x`). The removal pattern then
   requires a non-alphanumeric character after the token, so nothing is removed, although `_guard_g` lists the
   token as removed. 318 of the 1,518 vectors are like this. So "after G, an unreturned CVE cannot remain" does
   not hold. The verifier's REJECTED is the backstop, and on the device it catches every such case
   (`tests/grounding.rs`, `conductor-mock/tests/grounding.rs`). **Possible fix, Neuro's call:** remove the
   detected span by position instead of by a second pattern.

## Update: guards A and E on the device path (2026-11-24, from the Neuro host)

`neuro_contract::guard` mirrors `tools/neuro-research/guard.py` (`redact_all`, `echoes`) and the summary of
`run_eval.py`'s `template_backend`, which guard E falls back to. As with G, it is checked against vectors from
Neuro's own functions and has a drift gate on the Python sources.

- **Order on the device:** A on the way in; on the way out E, then G, then the verifier.
- **Guard A** is applied to the cards and to every tool result before a provider sees them. The schema's ids are
  those of the shown (redacted) context, as `run_eval.py` does with `--guard A`.
- **Guard E** reads the cards as the device wrote them, not the redacted ones. A fallback is a ledger record
  (`EchoFallback`) with the hash of the replaced prose. Verdict, evidence, entities and next step are kept.
- **Guard G and the grounding checks** now also read the cards as written (before, they read the prompt, which
  held the same bytes).

**Neuro's answers to three questions (2026-11-24), and what the device does:**
1. **E reads the original context, tool results included.** Done: the harness keeps every tool result as received
   (never shown to a provider) and E checks the cards and those results. The template sentence is still built
   from the cards only; Conductor's tool-result lines are not fact cards.
2. **English only on the device is fine.** The Romanian template stays mirrored and tested, and unselected.
3. **ASCII semantics are fine for cards** (`quote_untrusted` writes quoted values as ASCII JSON), on two conditions:
   - *Refusal must fail closed.* It does: a context guard A refuses is never sent (the job aborts), an answer E
     cannot read counts as an echo, and a template that cannot be written rejects the answer.
   - *Tool results may carry raw non-ASCII.* Guard A and E's test are not ASCII-only: character counts, the
     word count and `INSTRUCTION_LIKE` follow Python on Unicode text, including the characters `re.I` folds onto
     `i` and `s` (long s, dotless i, dotted capital I). The vectors and a harness test cover non-ASCII values.
     The ASCII-only parts are `\S`, `\d`, `\w` and `strip` in the template's row patterns, which read cards.
   - If the compressor's `quote_untrusted` is ported later, it must use the same folding: an ASCII-only
     matcher would under-flag.

**Not done:** the ftFg fidelity run on dev v8 builds its prompts without guard A (the tool predates this). It
compares the two runtimes on identical prompts, so the result stands, but the prompts are not the guarded ones
Neuro's gates used. **Since 2026-11-25** the tool takes `--guard-a`; see the 2026-11-25 update below.

**Fidelity result, ftFg on dev v8 (2026-11-24):** 270 cases, 40,428 teacher-forced steps. Template and token ids
equal in all cases; raw top-1 never disagrees beyond a near-tie; free runs are equal (156) or diverge first at a
near-tie (114). Three constrained choices differed beyond a near-tie, all from one cause: the contract automaton
allowed whitespace after a value, which llama.cpp 054a1ba's grammar does not. Fixed in `neuro_contract::Machine`;
the three cases agree after the fix. **Rerun of the full set with the fix (2026-11-25):** 270 cases, 0 constrained
choices beyond a near-tie, everything else unchanged. Details: `FIDELITY.md`.

## Update: the investigation request on the device side (2026-11-24, from the Neuro host)

Neuro published the investigation request as data: `tools/neuro-research/inv_contract.json` (hookprobe/hookprobe#1591),
generated from `inv_eval.py`. Doc 44 passed, so the investigation adapter is **ftM** (`9576cfac…dcc9`), not ftL.

- **Built:** `neuro_contract::inv`. It writes the prompt exactly as llama-server renders the request, and reads
  the answer. `tests/inv.rs` is the drift gate on the JSON file: system prompts, user framing, the five tools and
  their order, the settings, and the three test vectors' rendered prompts.
- **Checked on the Neuro host with ftM's GGUF:** the device tokenizer gives llama-server's token ids on all three
  prompts (673, 767 and 697 tokens).
- **The answer:** free text means no check. A call must be one of the five tools, with exactly its typed
  arguments and an entity alias of the shown context. This is the device's own strict reading, not a mirror of
  the grammar llama.cpp derives from `tools`.

**Not built, in order:**
1. Constrained decoding of the tool call in the engine. It needs the lazy grammar llama.cpp b12477 builds from
   `tools` (triggered by `<tool_call>` and a newline). **Asked of Neuro:** generated token ids for the three
   vectors, so the engine can be checked step by step as for triage.
2. The harness: Neuro's five tools as Conductor typed tools with per-call authorisation. The C0 tools
   (`evidence.get`, `flows.count`) are Conductor's own and stay.
3. The ftM fidelity run on the spent investigation sets, once 1 exists.

## Update: decoding the investigation answer (2026-11-24, from the Neuro host)

Neuro published the generated side of the three vectors and the server's own grammar
(`tools/neuro-research/inv_contract_gen.json`, hookprobe/hookprobe#1596). Item 1 of the list above is built.

- **`neuro_contract::inv::ToolMachine`** mirrors what llama-server applies: nothing until the generated text
  contains the trigger, then the GBNF the server derives from the five tools. `tests/inv_grammar.rs` reads that
  GBNF from the JSON file and compares the automaton with an independent interpreter of it, so a grammar change
  on the Neuro side (another llama.cpp build, another tool) fails there.
- **`neuro_lm::decode::generate_tool`** decodes under it. Under the grammar an added token is allowed only if it
  is one of the server's `preserved_tokens` and its text fits.
- **Against llama.cpp's CPU backend with ftM (`9576cfac…dcc9`), on the three vectors:** every one of the 57
  steps has the same raw top-1 and the same constrained choice, and the engine alone generates the same ids.
  In these vectors the grammar never had to overrule the model: the sampled token is always the raw top-1.

**Settled with Neuro (2026-11-24):**
1. **The entity stays an open string while decoding.** Doc 44 measured ftM that way, all 105 tool calls of its
   test set used an alias, and forcing an alias could turn a call that should be refused into a valid-looking call
   on the wrong alias. `parse_answer` refusing it afterwards fails closed. Closed entities would need a new
   pre-registered document, measured.
2. **How the trigger works, from Neuro's reading of the b12477 source** (`common/sampling.cpp`,
   `src/llama-grammar.cpp`; not re-read here). The trigger is two tokens, so it is a word trigger, matched as
   text over everything generated so far: ordinary tokens that spell it fire it too. On a match the grammar is
   fed from the first character of the trigger, and a token that runs past the trigger must fit the grammar from
   there. Text before the trigger never reaches the grammar. The automaton does exactly this.
3. **Neuro will say before regenerating `inv_contract_gen.json`** (another llama.cpp build or tool list), because
   the grammar test here reads its GBNF.

**Still open:** three synthetic vectors are not a fidelity run. That needs the spent investigation sets through
the fidelity tool, which still refuses them. **Done 2026-11-25**, see the next update.

## Update: the evidence cards on the device side (2026-11-25)

Neuro asked who builds the cards on the device and whether they equal its own. Nobody did. The function now
exists: `neuro_contract::cards::build_context` mirrors `semantic_compression.rep_cards` and `fill` (estimate token
counter, bytes / 4) and `e2e_neuro.py`'s rule that the context ends with the `REST` line.

- **Equal to Neuro's builder, byte for byte,** on Neuro's own vectors (`card_contract.json`: 22 windows of the E2E
  fixture, both alerts, 3 windows with no fact card), on 120 committed synthetic windows and on 6,400 more
  generated ones. `tests/data/CARD_VECTORS.md` has the generator and what it covers.
- **No float, no allocation.** Comparisons and printed numbers come from integers. Where Python's float rounding
  decides and real traffic meets it, the float is reproduced exactly: the mean gap (a device polling every
  5.000 s is not `periodic` for Python, because its float mean is just under 5) and the `out=…GB` figure.
  What is left as a stated difference is in the module's header: a coefficient of variation exactly on 0.1 or on
  a rounding boundary, a budget met exactly by `fill`'s float sum, and score ties that need a severity-5
  detection.
- **Two behaviours of the Python are kept as they are**, because the models were measured with them, and both
  are reported to Neuro: the port a detection is matched on for a pair with two or three ports comes from the
  iteration order of a Python `set`; and when exactly one card is dropped, the E2E path writes two `REST` lines.
- **A drift gate** reads Neuro's two sources and fails on a change to any mirrored constant or format string.

**Not covered, and what it waits for:**
1. **DNS and behaviour events.** Neuro's builder takes them; this function has no input for them. The E2E fixture
   has neither.
2. **Who calls it, and with what.** The function needs the window's flows, its detections and the baseline pairs.
   On the device those come from the kernel's flow table and the L1 alert; `e2e_neuro.py` also maps connection
   states to `rst` and attaches the alert as a detection. That mapping is the job issuer's and is not built.
3. **`CONTEXT` lines.** Still not carried by the job format (see the update on the investigation turn). The `REST` line is now
   produced here, so a job whose evidence is this function's output has it.
4. **Memory on the device.** The caller provides the working memory; a window that does not fit is an error. The
   sizes a real device window needs have not been measured.

## Update: fidelity on the investigation sets and with guard A (2026-11-25, from the Neuro host)

The fidelity tool now builds Neuro's investigation request (system prompt, user framing, the five tools spliced
verbatim, guard A, the server's lazy grammar and trigger) and decodes with `ToolMachine`. It also takes
`--guard-a` for triage, so the prompts are the guarded ones Neuro's gates used.

- **ftM on inv-blind v1 and v2 (spent), 150 cases each:** template and token ids equal in all 300 cases. 5,940
  teacher-forced steps: raw top-1 and the constrained choice never disagree beyond a near-tie (3 near-ties, all
  in v1). Free runs: 297 equal, 3 diverge first at a near-tie. Guard A changed 22 contexts in each set.
- **ftFg on dev v8, full rerun with the fixed automaton:** 270 cases, 0 beyond a near-tie on every check.
- **ftFg on dev v8 with `--guard-a`:** 270 cases, 39,061 teacher-forced steps, 0 beyond a near-tie; free runs
  154 equal, 116 diverge first at a near-tie. Two shards were stopped before their summary, so near-tie counts
  and margins cover 166 cases (`FIDELITY.md`).

Both are runtime-against-runtime on the same GGUF and request. Quality on these sets is Neuro's measurement.

**Still open:** the harness (Neuro's five tools as Conductor typed tools with per-call authorisation).
