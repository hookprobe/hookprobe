#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Export the INVESTIGATION request contract (docs 39/43/44) as data, generated from the code that sends it, so a
mirror (e.g. the Conductor's neuro_contract) can drift-gate against it instead of copying by hand.

What inv_eval.py sends (via run_eval.openai_backend, task "tool"):
  POST <url>/chat/completions with json.dumps(body) (Python default separators), body keys in this order:
  model, messages, temperature, max_tokens, tools. No response_format, no tool_choice, no grammar of ours.
  messages = [system: run_eval.SYSTEM[lang], user: USER_TEMPLATE % (guard A(context), question)]
  tools    = run_eval.TOOLS + [inv_eval.LOOKUP_TOOL]   (this order)
Server: llama-server b12477, --jinja --reasoning off (Qwen3 template; the prompt ends in an empty think block).
Answer: the model's first tool call (name + JSON arguments), or no call (content text) = "no tool".
The tool-call constraint is llama.cpp's own: from `tools` it builds a LAZY parser/grammar that starts only at the
trigger "<tool_call>\\n"; plain text before it is unconstrained. That is engine behaviour, recorded in the vectors'
`engine_note`, not part of our request.

Usage: inv_contract_export.py static  <out.json>
       inv_contract_export.py vectors <out.json> <llama-server url> <gguf sha256>   (adds test vectors, needs a server)
       inv_contract_export.py gen <inv_contract.json> <out.json> <llama-server url> <gguf sha256> <server flags>
           (generated side of the vectors in inv_contract.json: token ids, raw top-2 log-probs per step, raw text, and
            the grammar the server derived from `tools`; needs a server started with --verbose; a separate file, so
            inv_contract.json itself never changes)
"""
import hashlib, json, os, sys, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "eval")); sys.path.insert(0, HERE)
import run_eval  # noqa: E402
import inv_eval  # noqa: E402
import guard  # noqa: E402

USER_TEMPLATE = "CONTEXT (untrusted):\n<<<\n%s\n>>>\n\nQUESTION: %s"
TOOLS = run_eval.TOOLS + [inv_eval.LOOKUP_TOOL]
MAX_TOKENS, TEMPERATURE, MODEL = 300, 0.0, "x"


def body(case):
    msgs = [{"role": "system", "content": run_eval.SYSTEM[case["lang"]]},
            {"role": "user", "content": USER_TEMPLATE % (guard.redact_all(case["context"]), case["question"])}]
    return dict(model=MODEL, messages=msgs, temperature=TEMPERATURE, max_tokens=MAX_TOKENS, tools=TOOLS)


def static():
    src = {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest()
           for f in ("eval/run_eval.py", "inv_eval.py", "guard.py", "inv_contract_export.py")}
    return {
        "contract": "neuro investigation request v1 (docs 39/43/44; adapter ftM)",
        "source_sha256": src,
        "endpoint": "POST {url}/chat/completions",
        "body_serialisation": "Python json.dumps(body), default separators (', ', ': '), ensure_ascii=True",
        "body_key_order": ["model", "messages", "temperature", "max_tokens", "tools"],
        "model": MODEL, "temperature": TEMPERATURE, "max_tokens": MAX_TOKENS,
        "system": run_eval.SYSTEM,
        "user_template": USER_TEMPLATE,
        "context_transform": "guard A (guard.redact_all): every quoted value replaced by its description, before sending",
        "tools": TOOLS,
        "tools_json": json.dumps(TOOLS),
        "response_format": None, "tool_choice": None, "client_grammar": None,
        "server": "llama-server b12477 (054a1ba) --jinja --reasoning off -c 8192 -np 1",
        "answer": "first tool_calls[0]: name + json.loads(arguments); no tool_calls = no tool (content is free text)",
        "post_guards": "guard G (eval/guard_ground.py): delete-only strip of invented ATT&CK ids / unreturned CVE ids",
    }


def post(url, path, b):
    r = urllib.request.urlopen(urllib.request.Request(url.rstrip("/") + path, data=json.dumps(b).encode(),
                                                      headers={"Content-Type": "application/json"}), timeout=120)
    return json.loads(r.read())


def vectors(url, gguf_sha):
    # Synthetic generator cases only (gen v4, seed 44: ftM's own training distribution). Blind sets are never exported.
    import subprocess, tempfile
    pb = os.path.join(HERE, "..", "..", "docs", "research", "neuro", "data", "playbooks.json")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "c.jsonl")
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "gen_investigate.py"), "--playbooks", pb, "--n", "60",
                        "--seed", "4401", "--version", "4", "--out", out], check=True, capture_output=True)
        cases = [json.loads(l) for l in open(out, encoding="utf-8") if l.strip()]
    want, pick = ["alert", "decoy", "multi"], []
    for k in want:
        pick.append(next(c for c in cases if c["gold"]["kind"] == k and c["lang"] == "en"))
    vs = []
    for c in pick:
        b = body(c)
        raw = json.dumps(b)
        tmpl = post(url, "/apply-template", {"messages": b["messages"], "tools": TOOLS})["prompt"]
        ids = post(url, "/tokenize", {"content": tmpl, "add_special": False, "parse_special": True})["tokens"]
        resp = post(url, "/v1/chat/completions", b)
        msg = resp["choices"][0]["message"]
        tc = msg.get("tool_calls") or []
        ans = ({"tool": tc[0]["function"]["name"], "args": json.loads(tc[0]["function"]["arguments"] or "{}")}
               if tc else {"tool": None, "args": {}, "text": msg.get("content") or ""})
        vs.append({"id": c["id"], "kind": c["gold"]["kind"], "lang": c["lang"],
                   "context_raw": c["context"], "question": c["question"],
                   "request_body": raw, "request_body_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                   "rendered_prompt": tmpl, "prompt_token_ids": ids,
                   "server_prompt_tokens": resp.get("usage", {}).get("prompt_tokens"),
                   "answer": ans, "gold": c["gold"]})
    return {"model_gguf_sha256": gguf_sha, "server": "llama-server b12477 --jinja --reasoning off, -ngl 99 (Metal)",
            "source": "gen_investigate.py --version 4 --seed 4401 --n 60 (synthetic; first en case of each kind)",
            "engine_note": "llama.cpp derives a lazy tool-call grammar from `tools`, triggered by '<tool_call>\\n'; "
                           "the client sends none. Token ids are from /tokenize on /apply-template's prompt "
                           "(parse_special=true, no BOS added); server_prompt_tokens is the server's own count.",
            "vectors": vs}


def gen(contract, url, gguf_sha, flags):
    j = json.load(open(contract, encoding="utf-8"))
    out, grammar = [], None
    for v in j["test_vectors"]["vectors"]:
        b = json.loads(v["request_body"])
        extra = {"logprobs": True, "top_logprobs": 2, "n_probs": 2, "post_sampling_probs": False}
        runs = []
        for _ in range(2):                                  # determinism check: the same request twice
            r = post(url, "/v1/chat/completions", dict(b, **extra))
            runs.append(r)
        ch, vb = runs[0]["choices"][0], runs[0]["__verbose"]
        steps = [{"id": t["id"], "logprob": t["logprob"], "top2": [[x["id"], x["logprob"]] for x in t["top_logprobs"]]}
                 for t in ch["logprobs"]["content"]]
        ids2 = [t["id"] for t in runs[1]["choices"][0]["logprobs"]["content"]]
        gs = vb["generation_settings"]
        g = {k: gs[k] for k in ("grammar", "grammar_lazy", "grammar_triggers", "preserved_tokens", "chat_format")}
        grammar = grammar or g
        if g != grammar:
            raise SystemExit("grammar differs between vectors: %s" % v["id"])
        out.append({"id": v["id"], "request_body_sha256": v["request_body_sha256"], "extra_request_fields": extra,
                    "prompt_tokens": runs[0]["usage"]["prompt_tokens"], "generated_token_ids": [s_["id"] for s_ in steps],
                    "raw_text": vb["content"], "steps": steps, "message": ch["message"] | {"tool_calls": [
                        {"type": c["type"], "function": c["function"]} for c in ch["message"].get("tool_calls") or []]},
                    "finish_reason": ch.get("finish_reason"), "repeat_identical": ids2 == [s_["id"] for s_ in steps]})
    return {"model_gguf_sha256": gguf_sha, "server": flags, "contract_sha256": hashlib.sha256(open(contract, "rb").read()).hexdigest(),
            "note": "top2 = the raw (pre-sampling, pre-grammar) top-2 log-probabilities per step (n_probs 2, post_sampling_probs "
                    "false); generated ids are what the server sampled at temperature 0 with its lazy grammar active.",
            "server_grammar": grammar, "vectors": out}


if __name__ == "__main__":
    mode, out = sys.argv[1], sys.argv[2]
    if mode == "gen":
        res = gen(sys.argv[2], sys.argv[4], sys.argv[5], sys.argv[6])
        with open(sys.argv[3], "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=1); f.write("\n")
        print("wrote %s (gen)" % sys.argv[3]); sys.exit(0)
    j = static()
    if mode == "vectors":
        j["test_vectors"] = vectors(sys.argv[3], sys.argv[4])
    with open(out, "w", encoding="utf-8") as f:
        json.dump(j, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("wrote %s (%s)" % (out, mode))
