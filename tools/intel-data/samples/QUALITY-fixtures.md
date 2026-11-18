# Data quality report — 2026.11.18-99af6880baa1 (research)

Examples: **51**. Human-verified share: 0.0784. Synthetic share: 0.7059. Provenance completeness: 1.0. Licence completeness: 1.0.

## By collection and split

| collection/split | labels |
|---|---|
| attack_intelligence/dev | None: 1 |
| attack_intelligence/test | None: 1 |
| dns_intelligence/test | benign: 1, malicious: 1 |
| dns_intelligence/train | benign: 3, malicious: 1 |
| network_intelligence/test | malicious: 1 |
| network_intelligence/train | benign: 2, malicious: 2 |
| soc_reasoning/dev | benign: 4, malicious: 8 |
| soc_reasoning/test | malicious: 12 |
| soc_reasoning/train | benign: 8, malicious: 4 |
| vulnerability_intelligence/train | None: 2 |

## Sources and licences

| source | examples |
|---|---|
| hookprobe-synthetic-soc | 36 |
| f-tranco | 4 |
| f-iot23 | 3 |
| f-attack | 2 |
| f-urlhaus | 2 |
| f-cic | 2 |
| f-kev | 2 |

Licences: t-open (13), t-research (2), agpl-3.0-only (36)

## Labels

Ground-truth types: knowledge_base 4, feed_assertion 2, dataset_label 9, synthetic 36

Label-quality grades: high 4, low 2, medium 9, unknown 36

Class imbalance (max/min label count): dns_intelligence 2.0, network_intelligence 1.5, soc_reasoning 2.0

## Exclusions and contamination

- excluded exact_duplicates: 0
- build: dns_benign_dropped_conflict = 1

Contamination problems: **0**


## Missing fields (top)

| field | null count |
|---|---|
| target.confidence | 51 |
| detection.dst_port | 16 |
| target.severity | 15 |
| target.reasoning | 15 |
| target.recommended_action | 13 |
| dns.rcode | 6 |
| dns.client_ref | 6 |
| dns.transport | 6 |
| dns.window | 6 |
| record.observed_at | 4 |
| flow.service | 3 |
| attack_technique.detection | 2 |
| flow.conn_state | 2 |
| flow.history | 2 |
| vulnerability.cvss | 2 |
| vulnerability.published | 2 |

## Temporal coverage (records by year)

2017: 2, 2018: 3, 2025: 2, 2026: 40

## Tier-A baseline: heqk dga.rs on the DNS test split

| label@source | n | flagged (score ≥ 600) | rate |
|---|---|---|---|
| benign@f-tranco | 1 | 0 | 0.0 |
| malicious@f-urlhaus | 1 | 1 | 1.0 |
