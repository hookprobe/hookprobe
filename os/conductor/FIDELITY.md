# Fidelity check: the integer engine against llama.cpp, on the Neuro Mac

**What it answers.** Run on the same GGUF, does the heqk-native integer engine decode what llama.cpp decodes? If
it does, Neuro's quality results for ftFg carry over to the device. If it does not, beyond near-ties, that is an
engine bug. **This is not an evaluation.** Neuro owns quality; this check only compares the two runtimes
(Neuro's answers to the Conductor, question 2).

**Why on the Mac.** The model files stay on the Neuro host (operator decision). This cloud session cannot reach the
Mac (Remote Control is disabled by the admin). The tool talks only to a **loopback** llama-server, so no model,
case or answer leaves the machine.

## What the tool checks, per case

Each case is a `triage` or `injection` case of a spent set. Other task types are skipped.

1. **Template.** The prompt is rendered from `neuro_contract` alone and must equal llama-server's own rendering of
   the same messages (`/apply-template`).
2. **Tokenizer.** The engine's token ids must equal llama-server's (`/tokenize`).
3. **Reference.** llama-server decodes the same ids:
   - greedily;
   - under the same closed schema;
   - returning each chosen token and the **raw** top-2 log-probabilities (before the grammar).
4. **Teacher-forced engine.** At every step of the reference:
   - the raw top-1 must agree;
   - the engine's constrained choice (the same automaton the device uses) must equal llama.cpp's token;
   - the top-2 margin error is recorded.

   A step where llama.cpp's own top-2 gap is below `--tie` (default 0.5 nats) is a near-tie and is excused.
5. **Free run** (`--free-run`): the engine decodes on its own, with its exact speed-ups. It must produce the same
   tokens, or diverge first at a near-tie.

**Guards before anything runs:**
- the model must match its line in `SHA256SUMS`;
- the case set must be one Neuro named as spent: dev v8 or blind v3–v6. A sealed set is refused by its SHA-256.
- an inv-blind set is checked as investigation turns (below) and needs the investigation adapter.

The exit code is 0 only if the verdict is FAITHFUL.

**`--guard-a`** shows the model the context after guard A, as Neuro's gates do: `run_eval.py` applies
`guard.redact_all` to the context before the prompt and the schema are built, and so does the tool. Without the
option the prompts carry the raw quoted values.

**Investigation turns.** With an inv-blind set (v1 or v2, both spent) the tool checks the `investigate` cases
against the investigation adapter (ftM):

- the prompt is `neuro_contract::inv::write_prompt` on the context after guard A (always: it is the contract's
  `context_transform`);
- the template check sends Neuro's system prompt, user template and `tools` from `inv_contract.json` to
  `/apply-template`;
- the reference decodes on `/completion` under the grammar llama-server derives from the tools on
  `/chat/completions`, as recorded in `inv_contract_gen.json` (`--inv-gen`): lazy, triggered by `<tool_call>`
  and a newline, with its four preserved tokens. This route reproduces the generated ids of the three vectors in
  that file;
- the engine's side is `neuro_contract::inv::ToolMachine` with `pick_tool` and `generate_tool`.

Start that server with `--jinja --reasoning off`, on its own port:

```bash
llama-server -m ~/.cache/hookprobe-neuro/share-conductor/ftM-q8_0.gguf --port 8081 -c 8192 -np 1 -ngl 0 -t 4 --jinja --reasoning off --no-webui
```

```bash
cargo run --release -p tok-build --bin fidelity -- --dir ~/.cache/hookprobe-neuro/share-conductor --model ftM-q8_0.gguf --set <inv-blind>/blind_cases.jsonl --url http://127.0.0.1:8081 --free-run --out fidelity-ftM.md
```

One engine process uses one core and about 1.9 GB. Shards (`--shard K/N`) can share one server: the server
answers a case in seconds, the engine takes minutes.

## Run it

Prerequisites:
- a clone of this repository;
- Rust via `rustup` (the toolchain is pinned in `os/conductor/rust-toolchain.toml`);
- Neuro's llama-server build **b12477**;
- the staged folder `~/.cache/hookprobe-neuro/share-conductor/`.

1. Start the reference **on the CPU backend**. Neuro's fidelity rule compares against llama.cpp's CPU path, so
   use `-ngl 0`, not the Metal `-ngl 99` used for speed runs:

   ```bash
   llama-server -m ~/.cache/hookprobe-neuro/share-conductor/ftFg-q8_0.gguf --port 8080 -c 8192 -np 1 -ngl 0 --reasoning off --no-webui
   ```

2. Find dev v8 on the Neuro host by its hash (`d0edb353…`):

   ```bash
   shasum -a 256 <candidate>.jsonl
   ```

3. Start with a few cases, to learn the speed:

   ```bash
   cd os/conductor && cargo run --release -p tok-build --bin fidelity -- --dir ~/.cache/hookprobe-neuro/share-conductor --model ftFg-q8_0.gguf --set <dev-v8>.jsonl --url http://127.0.0.1:8080 --limit 5 --free-run --out fidelity-ftFg-5.md
   ```

4. Then run the whole set (`--limit` removed):

   ```bash
   cd os/conductor && cargo run --release -p tok-build --bin fidelity -- --dir ~/.cache/hookprobe-neuro/share-conductor --model ftFg-q8_0.gguf --set <dev-v8>.jsonl --url http://127.0.0.1:8080 --free-run --out fidelity-ftFg.md
   ```

**Options:**
- `--packed`: use the device's packed layout. Logits are identical either way; it needs about 2 GB more RAM.
- `--scalar`: force the scalar kernels. On Apple silicon the tool uses NEON with DotProd when the CPU reports it.
- `--max-tokens`: defaults to Neuro's 700.
- `--shard K/N`: check only every N-th case, starting at case K (0-based, counted over the triage and injection
  cases). One case takes about 2 minutes on one core of an M-series Mac, so the whole of dev v8 is about 11 hours
  in one process. Run N processes with K = 0 … N−1 against the same server instead; each loads the model (about
  1.9 GB) and writes its own report.

The report (`--out`) contains no case text: only case ids, token counts and per-check results. It is safe to
commit next to Neuro's results, or to paste back to the Conductor.

## Prompt for a Claude Code session on the Mac

> In my hookprobe clone, follow `os/conductor/FIDELITY.md`. Start llama-server b12477 on the CPU backend with
> `ftFg-q8_0.gguf` from `~/.cache/hookprobe-neuro/share-conductor/`. Find Neuro's dev v8 by its SHA-256
> (`d0edb353…`). Run the fidelity tool with `--limit 5 --free-run` first, then on the whole set. Don't upload the
> models or the set anywhere. Show me the report, and if the verdict is not FAITHFUL, list the failing case ids
> and steps.

## Tested here

Before being handed over, the tool was run in the cloud session against a stand-in server built from the same
integer engine, on the public Qwen3-1.7B Q8_0 GGUF and blind v3 (spent). That checks the tool's plumbing (HTTP,
guards, teacher forcing, free run, report), not fidelity. A stand-in that reports one confident wrong token must
make the tool say NOT FAITHFUL, and it does (see the PR for the numbers). llama.cpp itself could not be built in
the cloud session.

## Result: ftFg on dev v8 (2026-11-24, Neuro Mac)

Run: `ftFg-q8_0.gguf` (SHA-256 `0b0d276e…61ed`), dev v8 (`d0edb353…`, spent), llama-server b12477 (054a1ba) on the
CPU backend (`-ngl 0`), four shards with `--free-run`, near-tie threshold 0.5. The prompts are built without
guard A (see `NEURO_ALIGNMENT.md`).

| Check | Result |
|---|---|
| Cases | 270 checked (triage and injection); 50 skipped (other tasks) |
| Chat template equals llama-server's | 270 of 270 |
| Token ids equal llama-server's | 270 of 270 |
| Raw top-1 agrees (teacher-forced) | 40,428 steps; 153 near-ties; 0 disagreements beyond a near-tie |
| Top-2 margin where top-1 agrees (nats) | mean abs err 0.061, max 0.539 |
| Constrained choice equals llama.cpp's token | 152 near-ties; **3 beyond a near-tie** (`mal-019` step 174, `inj-023` step 168, `inj-058` step 56) |
| Free run equals llama.cpp's tokens | 156 equal, 114 diverge first at a near-tie, 0 diverge otherwise |

**The three disagreements were one bug in the contract automaton, not in the engine's arithmetic.** In each, the
summary string had just closed and the model's raw top-1 (the same on both sides) was refused by the grammar.
llama.cpp then took `,"` or `,\n`; the engine took a space or a newline, which its automaton allowed and which
had the higher logit on both sides. llama.cpp 054a1ba puts `space` after `{`, `[` and `,`, around `:`, and before
`]` and `}`; its value rules no longer end in `space`. The automaton still allowed whitespace after every value
and after the final `}`. `neuro_contract::Machine` now places whitespace as that grammar does
(`tests/contract.rs`).

**After the fix:** the three cases were run again (`--case`, with `--free-run`): 0 disagreements beyond a
near-tie, verdict FAITHFUL. **Not done:** the other 267 cases have not been run again with the fixed automaton.
The fix only removes choices, and llama.cpp's tokens were accepted in the three cases, so no change is expected
there, but it is not measured.

`--case ID` (repeatable) checks only those cases and prints every disagreeing step: the eight tokens before it,
both choices, and llama.cpp's ten raw candidates with the engine's logit for each and whether the automaton
allows it.
