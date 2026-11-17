## Weighted scores (1-5 scale; weights as specified)

| Architecture | value (25%) | eff (20%) | feas (15%) | rel (15%) | ux (10%) | cost (10%) | ip (5%) | **Weighted** | Veto flags |
|---|---|---|---|---|---|---|---|---|---|
| D — Evidence-first, model-last | 4 | 5 | 4 | 5 | 3 | 3 | 3 | **4.10** | — |
| C — Hybrid adaptive (on-device L2) | 4 | 4 | 3 | 4 | 4 | 2 | 3 | **3.60** | — |
| A — Extreme compact transformer | 3 | 3 | 2 | 2 | 3 | 3 | 3 | **2.70** | — |
| B — Recurrent edge intelligence | 2 | 3 | 1 | 2 | 2 | 2 | 3 | **2.10** | score 1 on feas |
| BASE — Conventional resident LLM | 2 | 1 | 2 | 1 | 3 | 4 | 1 | **1.90** | score 1 on rel |

## One-at-a-time weight sensitivity (each weight x0.5 / x1.5, renormalised)

| Weight changed | x0.5 winner (margin) | x1.5 winner (margin) |
|---|---|---|
| Practical intelligence & security value | D (+0.57) | D (+0.44) |
| CM5 resource efficiency | D (+0.44) | D (+0.55) |
| Technical feasibility & evidence | D (+0.46) | D (+0.53) |
| Reliability & security | D (+0.46) | D (+0.53) |
| User experience & autonomy | D (+0.58) | D (+0.43) |
| Development & maintenance cost (5 = cheapest) | D (+0.47) | D (+0.52) |
| Long-term differentiation / IP | D (+0.51) | D (+0.49) |

## Scenarios

| Scenario | Ranking (weighted score) |
|---|---|
| Efficiency-agnostic (eff = 0) | D 3.88 > C 3.50 > A 2.62 > BASE 2.12 > B 1.88 |
| UX-first (ux = 0.35) | D 3.88 > C 3.68 > A 2.76 > BASE 2.12 > B 2.08 |
| Cost-first (cost = 0.35) | D 3.88 > C 3.28 > A 2.76 > BASE 2.32 > B 2.08 |
| Research/IP-first (ip = 0.30) | D 3.88 > C 3.48 > A 2.76 > B 2.28 > BASE 1.72 |
| Value only | D 4.00 > C 4.00 > A 3.00 > BASE 2.00 > B 2.00 |

## Monte Carlo robustness (20,000 draws: Dirichlet weights around the stated ones, +-1 score noise)

| Architecture | Ranked first |
|---|---|
| D | 82.3% |
| C | 17.6% |
| A | 0.1% |
| BASE | 0.0% |
| B | 0.0% |
