# S1, frozen (doc 31 M3 S1; doc 35 M4 L1-IoT candidate)

| File | What |
|---|---|
| `s1_model.json` (SHA-256 `20f38f337863a934d825fd0cfecf57609865779a60cfd702063ff41a32c81df5`) | float model (`score > thr`) and its integer twin (u8 features, i16 weights, i32 accumulator, `acc > thr_q`) |
| `s1_golden.jsonl` (SHA-256 `16098b6f41b708434fada15cca8384ed053749a778cb02a4308d0ed0410e9da0`) | 95 windows (feature vector, u8 quantised, float score, i32 accumulator, both decisions); the windows nearest the threshold plus evenly spaced ones; for a Rust/no_std port |

**Made by:**

```
bench/s1_freeze.py --dev iot23_dev.jsonl,ctu13_dev.jsonl --out models/s1
```

The training inputs' SHA-256s are inside the JSON.

**Verified.** The float artefact reproduces `m3_run.py`'s S1 decisions exactly, and the integer twin makes the same
decisions too: 0 differences on IoT-23 test, CTU-13 test, both UNSW halves, and the UNSW second half cut with the
doc 20 rule (44,704 windows). The largest |accumulator| is far below 2^31; it is recorded in the JSON.

**Not deployable by itself.** M3 failed S1's recall gate (0.680). This artefact is the **candidate** for the
doc 35 M4 L1-IoT gate on new sealed data. A device would also need a fixed-point DNA v1 extractor (doc 32 §1) and a
signed package (heqk D3).

**Data.** The model is derived from IoT-23 (CC-BY-4.0) and CTU-13 (CC-BY) windows; attribution is in the intel-data
registry. The golden vectors are aggregate features of pseudonymised windows.
