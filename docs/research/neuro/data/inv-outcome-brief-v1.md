# Typed tool outcomes v1: labeller brief

This file is given verbatim to the outcome labeller. The labeller receives **only** this brief and one input file. It
has no access to the repository, its code or documents, training data, or any evaluation set.

## Your task

A network-security assistant on a home/SMB gateway investigates alerts by calling read-only tools. Each tool returns
a one-sentence result. You decide, for each result **on its own**, what the result means for the alert it was
called about. That is the typed outcome a well-built tool would return beside its sentence.

## Input

`results_only.jsonl` in your directory: one JSON object per line with `key`, `tool`, `alias` and `text`. Aliases
are `H1, H2…` (inside hosts), `R1, R2…` (remote hosts) and `D1, D2…` (domains). Some sentences are in Romanian.

| Tool | What it looked at |
|---|---|
| `lookup_reputation` | threat-intel reputation of a remote address or domain |
| `query_flows` | recent flows of a host |
| `query_dns` | recent DNS questions of a host |
| `lookup_exposure` | known-exploited weakness classes for a device's type or product |

The lines are shuffled. Each one is a separate investigation. Do not try to group them.

## Labels (exactly one per line)

- **`supports`**: the result adds evidence that the activity is malicious or unwanted. Examples: the remote is
  listed as malicious; the flows show the attack pattern spreading or continuing; data goes to an unknown outside
  host; the device's class has a known-exploited weakness that matches the activity.
- **`clears`**: the result gives a **specific benign explanation** for the activity. Examples: the remote belongs to
  the device's own vendor cloud or a known update or CDN host; the traffic is the owner's own backup, scanner or
  scheduled job; the owner confirms they did it.
- **`none`**: anything else: nothing found, no record, not listed, inconclusive or neutral. **The absence of bad
  evidence is not a benign explanation**: "not on any blocklist" or "no other flows" is `none`, not `clears`.

When a sentence mixes signals, label what it establishes most strongly. A specific benign explanation beats
`none`, and clear malicious evidence beats both.

## Output

`labels.jsonl` in your directory: one line per input line, `{"key": "<key>", "outcome": "supports" | "clears" | "none"}`.
Label every line exactly once. Work in the directory you are given and nowhere else.

Report back **only** the number of lines labelled and the count per label. **Do not paste any input text in your
reply.**
