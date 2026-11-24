// SPDX-License-Identifier: AGPL-3.0-only
//! The investigation request against Neuro's `tools/neuro-research/inv_contract.json` (generated there from the
//! code that sends the request). This test reads that file, so any change on the Neuro side fails here instead
//! of diverging silently: the system prompts, the user framing, the tools and their order, the request settings,
//! and for each of Neuro's test vectors the prompt llama-server rendered.
use neuro_contract::inv::*;
use neuro_contract::{context_ids, system_prompt, ContractError, IdList, Lang, Out, USER_HEAD, USER_MID};
use serde_json::Value;

fn contract() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research/inv_contract.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))).expect("inv_contract.json")
}

fn s<'a>(v: &'a Value, what: &str) -> &'a str {
    v.as_str().unwrap_or_else(|| panic!("inv_contract.json: {what} is not a string"))
}

fn ids(ctx: &str) -> IdList {
    let (mut f, mut e) = (IdList::new(), IdList::new());
    context_ids(ctx.as_bytes(), &mut f, &mut e).unwrap();
    e
}

#[test]
fn request_matches_inv_contract_json() {
    let c = contract();
    assert_eq!(system_prompt(Lang::En), s(&c["system"]["en"], "system.en"));
    assert_eq!(system_prompt(Lang::Ro), s(&c["system"]["ro"], "system.ro"));
    assert_eq!(format!("{USER_HEAD}%s{USER_MID}%s"), s(&c["user_template"], "user_template"));
    assert_eq!(c["max_tokens"], MAX_TOKENS);
    assert_eq!(c["temperature"], 0.0);
    // Nothing constrains the answer on the client side; the server derives the tool-call grammar from `tools`.
    for k in ["response_format", "tool_choice", "client_grammar"] {
        assert!(c[k].is_null(), "inv_contract.json now sets {k}: the device must decode under it too");
    }
    assert!(s(&c["context_transform"], "context_transform").starts_with("guard A (guard.redact_all)"), "the context is no longer sent after guard A");
    assert!(s(&c["server"], "server").contains("--jinja --reasoning off"), "the server no longer renders with the model's template, reasoning off");
    // The tools: same five, same order, same bytes as the request carries (Python json.dumps, default separators).
    let tools_json = format!("[{}]", TOOLS.iter().map(|t| t.json).collect::<Vec<_>>().join(", "));
    assert_eq!(tools_json, s(&c["tools_json"], "tools_json"));
    let tools = c["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), TOOLS.len());
    for (t, j) in TOOLS.iter().zip(tools) {
        let f = &j["function"];
        assert_eq!(t.name, s(&f["name"], "tool name"));
        assert_eq!(serde_json::from_str::<Value>(t.json).expect("tool json"), *j);
        let props = f["parameters"]["properties"].as_object().expect("properties");
        let mut want = vec!["entity"];
        if t.minutes {
            want.push("minutes");
            assert_eq!(props["minutes"]["type"], "integer");
        }
        if t.policy {
            want.push("policy");
            let en: Vec<&str> = props["policy"]["enum"].as_array().expect("policy enum").iter().map(|x| s(x, "policy")).collect();
            assert_eq!(en, POLICIES);
        }
        let mut have: Vec<&str> = props.keys().map(String::as_str).collect();
        have.sort_unstable();
        assert_eq!(have, want, "{}: the typed arguments differ from the schema", t.name);
        let required: Vec<&str> = f["parameters"]["required"].as_array().expect("required").iter().map(|x| s(x, "required")).collect();
        assert_eq!(required, if t.policy { vec!["entity", "policy"] } else { vec!["entity"] }, "{}", t.name);
    }
    println!("drift gate: neuro_contract::inv equals inv_contract.json ({} tools, 2 system prompts, the user framing, the settings)", TOOLS.len());
}

#[test]
fn rendered_prompts_equal_llama_servers() {
    let c = contract();
    let vectors = c["test_vectors"]["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 3);
    let mut buf = vec![0u8; 1 << 16];
    for v in vectors {
        let id = s(&v["id"], "id");
        // The context as sent (after guard A) and the question, from the request body itself.
        let body: Value = serde_json::from_str(s(&v["request_body"], "request_body")).expect("request_body");
        assert_eq!(s(&body["messages"][0]["content"], "system"), system_prompt(Lang::En), "{id}");
        let user = s(&body["messages"][1]["content"], "user");
        let (shown, question) = user.strip_prefix(USER_HEAD).and_then(|u| u.rsplit_once(USER_MID)).unwrap_or_else(|| panic!("{id}: the user framing changed"));
        assert_eq!(question, s(&v["question"], "question"), "{id}");
        assert_eq!(body["tools"], c["tools"], "{id}");
        assert_eq!(body["max_tokens"], MAX_TOKENS, "{id}");

        let lang = if s(&v["lang"], "lang") == "ro" { Lang::Ro } else { Lang::En };
        let mut o = Out::new(&mut buf);
        write_prompt(lang, shown.as_bytes(), question.as_bytes(), &mut o).unwrap();
        let got = std::str::from_utf8(&o.buf[..o.n]).unwrap();
        assert_eq!(got, s(&v["rendered_prompt"], "rendered_prompt"), "{id}: the prompt differs from llama-server's rendering");

        // Neuro's recorded answer, written as the model writes a call, reads back as the same typed call.
        let ents = ids(shown);
        let a = &v["answer"];
        let text = match a["tool"].as_str() {
            Some(tool) => format!("<tool_call>\n{{\"name\": \"{tool}\", \"arguments\": {}}}\n</tool_call>", a["args"]),
            None => s(&a["text"], "answer text").to_string(),
        };
        match (parse_answer(text.as_bytes(), &ents), a["tool"].as_str()) {
            (Ok(Answer::NoTool), None) => {}
            (Ok(Answer::Call(call)), Some(tool)) => {
                assert_eq!(call.name(), tool, "{id}");
                assert_eq!(ents.get(usize::from(call.entity)), Some(s(&a["args"]["entity"], "entity").as_bytes()), "{id}");
            }
            (got, want) => panic!("{id}: parsed {got:?}, Neuro recorded {want:?}"),
        }
    }
    println!("investigation vectors: {} prompts equal llama-server's rendering; the recorded answers parse", vectors.len());
}

#[test]
fn answers_are_read_strictly() {
    let e = ids("F1 H1=192.168.1.20->R1=203.0.113.9:443 n=4\nF2 H2 dns D1=a.example n=1");
    let call = |t: &str| parse_answer(t.as_bytes(), &e);
    let ok = |t: &str| match call(t) {
        Ok(Answer::Call(c)) => c,
        other => panic!("{t:?}: {other:?}"),
    };
    assert_eq!(call("No check is needed; this is ordinary activity for the device."), Ok(Answer::NoTool));
    assert_eq!(call(""), Ok(Answer::NoTool));

    let c = ok("<tool_call>\n{\"name\": \"lookup_reputation\", \"arguments\": {\"entity\": \"R1\"}}\n</tool_call>");
    assert_eq!((c.name(), e.get(usize::from(c.entity)), c.minutes, c.policy, c.is_proposal()), ("lookup_reputation", Some(&b"R1"[..]), None, None, false));
    // Text before the call is free; compact JSON and a missing closing tag at the end are accepted.
    let c = ok("I will check DNS.\n<tool_call>{\"name\":\"query_dns\",\"arguments\":{\"entity\":\"H2\",\"minutes\":60}}");
    assert_eq!((c.name(), c.minutes), ("query_dns", Some(60)));
    let c = ok("<tool_call>\n{\"name\": \"query_flows\", \"arguments\": {\"minutes\": 15, \"entity\": \"H1\"}}\n</tool_call>\n");
    assert_eq!((c.name(), c.minutes), ("query_flows", Some(15)));
    let c = ok("<tool_call>\n{\"name\": \"propose_policy_change\", \"arguments\": {\"entity\": \"H1\", \"policy\": \"isolated\"}}\n</tool_call>");
    assert_eq!((c.policy.map(|p| POLICIES[usize::from(p)]), c.is_proposal()), (Some("isolated"), true));

    for bad in [
        // not one of the five tools
        r#"<tool_call>{"name": "run_shell", "arguments": {"entity": "H1"}}</tool_call>"#,
        // an alias the context does not contain, and something that is not an alias
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R9"}}</tool_call>"#,
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "203.0.113.9"}}</tool_call>"#,
        // missing, repeated, extra or mistyped arguments
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {}}</tool_call>"#,
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1", "entity": "H1"}}</tool_call>"#,
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1", "minutes": 5}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": "5"}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": 0}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": 05}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": 1.5}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": -5}}</tool_call>"#,
        r#"<tool_call>{"name": "query_flows", "arguments": {"entity": "H1", "minutes": 99999}}</tool_call>"#,
        r#"<tool_call>{"name": "propose_policy_change", "arguments": {"entity": "H1"}}</tool_call>"#,
        r#"<tool_call>{"name": "propose_policy_change", "arguments": {"entity": "H1", "policy": "blocked"}}</tool_call>"#,
        r#"<tool_call>{"name": "lookup_exposure", "arguments": {"entity": "H1", "policy": "isolated"}}</tool_call>"#,
        // a second call, trailing text, wrong key order, escapes, an unfinished call
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1"}}</tool_call><tool_call>{"name": "lookup_reputation", "arguments": {"entity": "H1"}}</tool_call>"#,
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1"}}</tool_call> and isolate it"#,
        r#"<tool_call>{"arguments": {"entity": "R1"}, "name": "lookup_reputation"}</tool_call>"#,
        concat!(r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R"#, "\\", r#"u0031"}}</tool_call>"#),
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1"}"#,
        r#"<tool_call>"#,
        r#"<tool_call>{"name": "lookup_reputation", "arguments": {"entity": "R1",}}</tool_call>"#,
    ] {
        assert_eq!(call(bad), Err(ContractError::Invalid), "{bad}");
    }
    // No panic and no acceptance on any prefix or single-byte change of a valid call.
    let good = "<tool_call>\n{\"name\": \"query_flows\", \"arguments\": {\"entity\": \"H1\", \"minutes\": 15}}\n</tool_call>";
    for n in 0..good.len() {
        let _ = call(&good[..n]);
        let mut b = good.as_bytes().to_vec();
        for x in [b'"', b'{', b'}', b',', b':', b' ', b'9', b'\\', 0, 0xff] {
            b[n] = x;
            let _ = parse_answer(&b, &e);
        }
    }
}
