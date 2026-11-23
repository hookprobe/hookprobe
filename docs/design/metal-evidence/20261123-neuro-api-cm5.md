<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Neuro N0 evidence API on CM5, shipping feature set + neuro (2026-11-23)

**Class: CM5 metal.** Image `napi-dd95d743` = main `dd95d743` built with exactly the proposed MVP shipping set
`hboot,apmc,wifi-bigtx,appersist,wpa3,neuro` (bench dev keys + bench config, +debug access; fits after #1519). Run:
OTA install (trial → COMMITTED), Pi browsing, wait for a real UTC hour close, read `GET /api/neuro`, OTA back to
am35B. Script: the `napi.sh` steps in this doc's PR.

| Check | Result |
|---|---|
| `GET /api/neuro` without a session | **ok**: 401 |
| An hour closed under Wi-Fi load | **ok** |
| `enabled`, `tier` N0, `kind` evidence_only, `state` running | **ok** |
| `learning_hours` 24 / `relearning_hours` 336 | **ok** |
| counters: fed 2,321, hours_closed 1, hours_failed 0, events_dropped 0 | **ok** |
| 1 evidence record, `device_state` learning, `rank` false (fresh boot: device < 24 h) | **ok** |
| no reset since load → `relearning_since` null, server_resets 0 | **ok** |
| AP loop worst gap 464 ms (< 2 s) | **ok** |
| no panic / crash; bench restored to am35B | **ok** |

```
{"enabled":true,"tier":"N0","kind":"evidence_only","state":"running","relearning_since":null,"learning_hours":24,"relearning_hours":336,"devices_tracked":1,"counters":{"events_fed":2321,"events_dropped":0,"hours_closed":1,"hours_failed":0,"results":1,"deviant":1,"server_resets":0,"slot_evictions":0},"evidence":[{"mac":"dc:a6:32:a4:b6:88","hour_start":1795435200000,"driver":"volume","score_q8":3583,"parts_q8":[3583,541,2557,1024,2189],"first_seen":1795436697000,"hours_since_first_seen":0,"device_state":"learning","rank":false}]}…
[NEURO exc] events n=420 avg=633ns max=3055ns | close_hour n=1 avg=3629ns max=3629ns | other n=1 avg=907ns max=907ns
```

Not covered: `relearning` on metal (needs an el0-neuro reset + 14 d; the rule is covered by `[P-neuro-api]` in
QEMU), and `warm` (needs > 24 h on one device).
