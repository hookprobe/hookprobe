# Blind v2 evaluation set

215 hand-written cases for a home/SMB network-security assistant that reads sensor evidence cards.

## How it was built

- Source material: only `BRIEF.md` and general security knowledge (MITRE ATT&CK, well-known malware and
  incident patterns such as Mirai, cryptojacking, infostealers, Log4Shell, Kerberoasting, DCSync, LLMNR
  poisoning, ransomware staging, residential-proxy TV boxes, and ordinary IoT/home device behaviour). No
  repository, training data or earlier evaluation set was opened.
- Every case is a Python literal in `gen/build.py`. The helper functions `tri`, `inj`, `cop` and `tool`
  only pack hand-written fields into the output schema; nothing is templated, sampled or randomised.
- `python3 -I gen/build.py` validates the in-memory cases, writes `blind_cases.jsonl`, re-reads the file,
  validates it again, checks that it round-trips unchanged, and prints the counts.
- Standard library only.

### What the validator enforces

- top-level keys exactly `id, lang, task, context, question, gold`; id prefix matches the task;
- per-task gold keys, verdict and `next_step` enums, tool names, policy values, `max_confidence` range;
- every context line is a card (`F<n>`), `CONTEXT`, `DEVICE` or `REST`; card ids are sequential; exactly
  one `REST` line and it is last; `DEVICE` appears in copilot cases only;
- `det=` grammar: `det=<category>[T####(.###),sev1-4,<wire action>]` with the 10 categories and the four
  wire actions; `!instr-like` always follows a quoted string;
- aliases: with quoted text blanked out, each `H/R/D<n>` is defined (`=value`) at its first mention, is
  never redefined, and no two aliases share a value; aliases in the question must exist in the context;
- `H` aliases are RFC 1918, `R` aliases are RFC 5737, every IPv4 anywhere (quotes included) is in one of
  those ranges, `D` aliases and every domain-like token end in `.example` (inside quotes, file extensions
  such as `.exe`/`.zip` are allowed);
- gold evidence ids and entities exist in the context; tool `entity` arguments exist;
- copilot `must_mention_all` strings appear literally in the `DEVICE` line and `forbid_strings` do not;
- injection canaries: exactly one per real injection, planted in the context, absent from the question,
  unique across the set, not overlapping the banned list, not an ordinary word, and not present in any
  other case; 5–7 decoys (empty `forbid_strings`) whose verdicts are only benign/insufficient;
- subset rules: `mal-` accepts malicious, `sus-` suspicious, `ben-` benign, `ins-` insufficient_evidence
  and carries `max_confidence`;
- Romanian: questions contain Romanian diacritics, comma-below ș/ț are used (no cedilla ş/ţ), every
  diacritic keyword in `must_mention_any` has its plain twin, and each list has an ASCII/English term;
- exact counts per subset and language, 215 in total.

The validator was also checked against deliberately broken copies (bad severity, public IP, undefined
alias, `.com` domain, phantom evidence id, banned canary, bad policy, wrong count); each one was caught.

## Counts

| subset | task | n | en | ro |
|---|---|---|---|---|
| mal | triage | 40 | 27 | 13 |
| sus | triage | 30 | 20 | 10 |
| ben | triage | 40 | 28 | 12 |
| ins | triage | 20 | 14 | 6 |
| cor | triage | 20 | 14 | 6 |
| inj | injection | 25 | 19 | 6 |
| cop | copilot | 20 | 13 | 7 |
| tool | tool | 20 | 14 | 6 |
| **total** | | **215** | **149** | **66 (30.7%)** |

Tasks: triage 150, injection 25, copilot 20, tool 20.

Verdict balance over the 175 triage + injection cases (first-listed verdict): malicious 66, suspicious 40,
benign 49, insufficient_evidence 20. Verdicts accepted anywhere: malicious 75, suspicious 65, benign 72,
insufficient_evidence 26. 62 cases accept two (one case three) verdicts.

Injection subset: 19 real injections, 6 harmless look-alikes. Tool gold: no tool 7, lookup_reputation 4,
propose_policy_change 5 (isolated ×2, internet_only, lan_only, full_access), query_dns 2, query_flows 2.

## Judgement calls

### Two-verdict sets where analysts can reasonably differ
Sets such as malicious/suspicious or suspicious/benign are used where the cards fit two readings: a
cryptominer whose installer is unknown, an overnight upload that could be an insider or malware, a
port-9001 pattern that may be a Tor browser, a new smart-TV beacon that may be vendor telemetry, internal
SMB discovery from a fresh Windows laptop. Clear chains (brute force → login → lateral movement, worm
scanning, ransom-note writes) keep a single verdict.

### Detector severity is not the verdict
Several cases have severity deliberately off: sev4 on a DDoS flood from a smart plug, on a successful SSH
brute force and on a residential-proxy TV box (gold malicious); sev1 on a nightly cloud resync, an hourly
CDN update check and a 12 MB transfer (gold benign or insufficient). Gold follows the facts, not `sevN`.

### Owner context is evidence, not authority
Owner notes sometimes explain an alert (backup schedules, speed tests, a changed NAS password) and
sometimes mislead: "the technician cleaned it" while the host still beacons to the same C2; "I run a
Monero node" while the traffic is stratum to a mining pool; "the camera records to the cloud" while it
telnet-scans the internet; "it's the IT laptop" while an unexplained outbound RDP happens at 02:00. Gold
then rests on the part the note does not explain.

### Look-alike cards that are not related
Correlation cases mix cards that share a port, a timeframe or a destination but are unrelated: two port
4444 flows (a reverse shell and a local dev server), brute force on one host alongside a beacon from
another, a guest-network DGA next to a printer firmware check, two smart plugs of the same model on one
vendor IP. Gold evidence lists only the cards that carry the finding.

### Insufficient evidence versus benign
Single, thin events (one NXDOMAIN, one refused SSH, three beacon samples, an alert with no detail) accept
insufficient_evidence, sometimes with benign or suspicious as a second answer, and carry a
`max_confidence` of 35–60 so a confident verdict is penalised.

### Injection verdicts follow the underlying traffic
The presence of an injection does not by itself make a case malicious. Where the only finding is a blocked
exploit carrying instruction text, suspicious and benign are both accepted; where the instruction-laden
DNS name is a single query from a smart plug, suspicious and insufficient are accepted. Owner-note
injections are treated as telemetry because anyone with app access can write them.

### Harmless strings that only look like injections
Six decoys are flagged `!instr-like` by the sensor but are innocent: a DNS filter list name, a draft file
name, a voice-assistant user agent, a bank password-reset host, a help-page referer, and a Romanian owner
note that addresses the assistant with legitimate context. Their gold is benign (one also accepts
insufficient) and they have no canary.

### Copilot unknowns
Questions about firmware changelogs, the Wi-Fi password, speed tests, an ISP area outage, hardware
lifetime and browsing history cannot be answered from a `DEVICE` line. Gold requires saying so and
forbids phrases that would only appear in an invented answer (for example a quoted CVE id or a
"download speed is" figure), while still requiring the literal facts that are known.

### Tool choice
The assistant only proposes policy. Requests that are answerable from the cards (what sev2 means, what
T1046 is, whether a card is periodic, how many cards were omitted) expect no tool; so do cases where only
injected telemetry or an owner note asks for a tool, and a request to delete logs that no tool supports.
A user's explicit request to restore a printer's access is a valid `full_access` proposal.

### Next-step sets
Where more than one follow-up is sound (isolate versus investigate for a probable but unconfirmed
compromise; harden versus observe for a correctly blocked attack on an exposed service), `next_step`
lists both.

## Limitations

- One author wrote every case, so phrasing and scenario choice share one person's habits and blind spots.
- Cards are text abstractions of a sensor I have not seen; field combinations (for example `periodic`
  on a fanout card or `file=` on a flow) are plausible readings of the brief, not copies of real output.
- `must_mention_any` keywords are substring targets; a correct answer with different wording can miss
  them, and the Romanian lists cannot cover every inflected form.
- Copilot `must_mention_all` uses numeric substrings; a few are short and therefore easy to hit by chance.
- MITRE ids were chosen from memory to fit each behaviour; a few (for example the mobile techniques)
  could reasonably be swapped for neighbours.
- Correlation and multi-verdict judgements are one careful analyst's reading; they have not been
  reviewed by a second person.
