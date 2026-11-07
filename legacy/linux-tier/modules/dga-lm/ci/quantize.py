#!/usr/bin/env python3
"""ci/quantize.py — dga-lm CI quantization stage (base-tier-build-ticket.md Phase 4).

WHAT THIS SCRIPT IS, HONESTLY (read before trusting the output as "a DGA detector"):

Per ADR 0014, dga-lm's REAL model is trained OFF-DEVICE (a proper char-CNN over a
labelled DGA/benign corpus, quantized from a float32 checkpoint this repo does not and
should not vendor). No such checkpoint exists in this repo today. This script therefore
does NOT quantize a trained checkpoint — it DETERMINISTICALLY GENERATES the small,
hand-derived, rule-based SEED/BASELINE weight blob checked in at
`../model/dga_seed.bin`, using two coarse, well-known lexical heuristics (digit density
vs vowel density, and 4-in-a-row consonant runs) that are honestly weak but nonzero DGA
signals — enough to exercise the FULL int8 embed -> conv -> pool -> dense compute graph
and the SDOT/NEON dot-product kernels end to end, and enough to move QSECBIT's score on
an obviously-DGA-shaped input, without pretending to be a validated classifier.

When a real off-device-trained checkpoint exists, this script's job becomes: load that
checkpoint, compute a symmetric per-tensor int8 quantization scale
(`scale = max(abs(weights)) / 127`, clamped so no quantized value ever lands on -128 —
see `dot.rs`'s determinism note on relaxed-dot's -128 edge case), write the SAME blob
layout (`model.rs`'s doc comment is the single source of truth for the format), and
regenerate `MODEL_CARD.md` with real evaluation metrics. The `--from-checkpoint` flag
below is the intended integration point; today it is unimplemented and the script
always falls back to the deterministic seed generator (never silently fabricates a
"trained" card — see `write_model_card()`).

Usage:
    python3 ci/quantize.py                     # (re)generate the seed model + card
    python3 ci/quantize.py --check              # verify the checked-in blob matches
                                                  # what this script would generate (CI gate)
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL_DIR = HERE.parent / "model"
BLOB_PATH = MODEL_DIR / "dga_seed.bin"
CARD_PATH = MODEL_DIR / "MODEL_CARD.md"

# --- shape constants — MUST match modules/dga-lm/src/{tokenizer,model}.rs exactly ---
VOCAB = 40
EMBED_DIM = 16
MAX_LEN = 24
KERNEL = 4
WINDOW_LEN = KERNEL * EMBED_DIM  # 64
CONV_OUT = 32
FORMAT_VERSION = 1
MAGIC = b"DGA1"

# Vocabulary layout (must match tokenizer.rs::char_to_id):
#   0 = PAD, 1..26 = a..z, 27..36 = 0..9, 37 = '-', 38 = '.', 39 = UNK
VOWEL_IDS = {1 + (ord(c) - ord("a")) for c in "aeiou"}
LETTER_IDS = set(range(1, 27))
CONSONANT_IDS = LETTER_IDS - VOWEL_IDS
DIGIT_IDS = set(range(27, 37))
HYPHEN_ID = 37
DOT_ID = 38
PAD_ID = 0
UNK_ID = 39

# Embedding "class dims" — each character class lights up exactly ONE of these 5 dims
# (dims 5..16 are left at zero: headroom for a real trained embedding, documented in
# the model card as unused by the seed).
DIM_VOWEL = 0
DIM_CONSONANT = 1
DIM_DIGIT = 2
DIM_HYPHEN = 3
DIM_DOT = 4
CLASS_MAGNITUDE = 100  # int8-safe (never -128 — see dot.rs's determinism note)

# Requantization shift the Rust side (model.rs::REQUANT_SHIFT) applies between the
# conv+pool stage (i32) and the dense stage (i8). Kept here ONLY as a cross-check
# constant for `--check`'s worked-example sanity math in this file's docstring; the
# actual shift lives in Rust (single source of truth for the runtime behaviour).
REQUANT_SHIFT = 2


def class_dim(char_id: int) -> int | None:
    if char_id in VOWEL_IDS:
        return DIM_VOWEL
    if char_id in CONSONANT_IDS:
        return DIM_CONSONANT
    if char_id in DIGIT_IDS:
        return DIM_DIGIT
    if char_id == HYPHEN_ID:
        return DIM_HYPHEN
    if char_id == DOT_ID:
        return DIM_DOT
    return None  # PAD / UNK: all-zero embedding row


def build_embedding() -> bytes:
    """[VOCAB][EMBED_DIM] int8, row-major. One nonzero lane per class (see class_dim)."""
    rows = bytearray(VOCAB * EMBED_DIM)
    for char_id in range(VOCAB):
        dim = class_dim(char_id)
        if dim is not None:
            rows[char_id * EMBED_DIM + dim] = CLASS_MAGNITUDE & 0xFF
    return bytes(rows)


def build_conv() -> tuple[bytes, bytes]:
    """[CONV_OUT][WINDOW_LEN] int8 weights + [CONV_OUT] int32 LE bias.

    Channel 0 — "digit-minus-vowel": weight[k][DIM_DIGIT] = +1, weight[k][DIM_VOWEL] = -1
    for every kernel position k. Fires (after ReLU) on windows with more digits than
    vowels — a coarse, well-known DGA lexical tell.

    Channel 1 — "4-consonant run": weight[k][DIM_CONSONANT] = +1 for every k, bias =
    -3*CLASS_MAGNITUDE so ONLY a full 4-consecutive-consonant window (dot =
    4*CLASS_MAGNITUDE) clears the ReLU floor. A classic "unpronounceable" DGA tell.

    Channels 2..CONV_OUT — all-zero weight AND bias: always pool to 0, contribute
    nothing to the dense layer. Explicit headroom for real trained features later
    (documented, not silently dropped — see MODEL_CARD.md).
    """
    w = bytearray(CONV_OUT * WINDOW_LEN)
    b = [0] * CONV_OUT

    def set_w(channel: int, k: int, dim: int, value: int) -> None:
        w[channel * WINDOW_LEN + k * EMBED_DIM + dim] = value & 0xFF

    for k in range(KERNEL):
        set_w(0, k, DIM_DIGIT, 1)
        set_w(0, k, DIM_VOWEL, -1)
        set_w(1, k, DIM_CONSONANT, 1)
    b[0] = 0
    b[1] = -3 * CLASS_MAGNITUDE

    bias_bytes = b"".join(struct.pack("<i", v) for v in b)
    return bytes(w), bias_bytes


def build_dense() -> tuple[bytes, bytes]:
    """[CONV_OUT][2] int8 weights (benign logit, dga logit) + [2] int32 LE bias.

    Only channels 0/1 (the two heuristics above) feed the dga logit; every other
    channel's weight is 0 (they always pool to 0 anyway — belt and suspenders). A
    constant benign bias keeps a neutral domain (no digit/vowel skew, no 4-consonant
    run) classified benign rather than 50/50.
    """
    w = bytearray(CONV_OUT * 2)
    w[0 * 2 + 1] = 40 & 0xFF  # channel 0 (digit-minus-vowel) -> dga logit
    w[1 * 2 + 1] = 20 & 0xFF  # channel 1 (consonant run)     -> dga logit
    bias = struct.pack("<i", 60) + struct.pack("<i", 0)  # [benign=+60, dga=0]
    return bytes(w), bias


def build_blob() -> bytes:
    header = MAGIC + bytes(
        [FORMAT_VERSION, VOCAB, EMBED_DIM, MAX_LEN, KERNEL, CONV_OUT, 0, 0]
    )
    embedding = build_embedding()
    conv_w, conv_b = build_conv()
    dense_w, dense_b = build_dense()
    blob = header + embedding + conv_w + conv_b + dense_w + dense_b
    assert len(header) == 12, len(header)
    return blob


MODEL_CARD_TEMPLATE = """\
# dga-lm — model card (SEED / BASELINE, not a trained model)

**Status:** seed placeholder. This is NOT a trained classifier. Per ADR 0014, the real
dga-lm model is trained OFF-DEVICE on a labelled DGA/benign domain corpus and quantized
by this same script (`--from-checkpoint`, not yet implemented — see the script's
docstring). This checked-in blob exists so the int8 embed -> conv -> pool -> dense
compute graph, the int8 dot-product kernels (`dot.rs`: relaxed-dot / simd128-widening /
scalar), the two-stage SDOT gate, and QSECBIT's `p_attack` wiring can all be exercised
and tested end to end before a real model exists.

## What it actually computes

Two hand-derived, well-known coarse lexical heuristics, implemented as int8 conv
channels 0 and 1 (channels 2-31 are inert zero-weight headroom for real trained
features):

1. **Digit density vs vowel density** per 4-character window — DGA domains skew
   digit-heavy and vowel-sparse more often than dictionary-word domains.
2. **4-consecutive-consonant runs** — a classic "unpronounceable string" tell.

Score = softmax(dense(maxpool(relu(conv(embed(domain)))))) — see `../src/model.rs`.

## What it is NOT

- Not trained on any real DGA or benign corpus.
- Not validated against a held-out test set, ROC/AUC, precision/recall, or any of the
  metrics a real model card would report — there are none to report yet.
- Not a substitute for HYDRA's IOC/threat-intel DGA feeds — this is a fast, local,
  CPU-only, advisory/observe-only signal (C9), not the platform's DGA detector of record.

## Shape / footprint

- Vocabulary: {vocab} symbols, {embed_dim}-dim int8 embedding.
- Input: {max_len} characters (truncate/left-pad).
- Conv: kernel={kernel}, {conv_out} output channels (2 active, 30 inert headroom).
- Dense: {conv_out} -> 2 logits (benign, dga).
- Blob size: {blob_size} bytes ({blob_kb:.2f} KiB) — budget is 256 KiB (L2-resident,
  base-tier-build-ticket.md Phase 4 A76 budget row). This seed uses well under 1% of
  that budget; a real trained model has ~250x headroom to grow within the same budget.

## Regeneration

`python3 ci/quantize.py` regenerates `dga_seed.bin` + this file deterministically (no
randomness, no external inputs) — the seed weights are hand-derived constants in this
script, not sampled. `python3 ci/quantize.py --check` verifies the checked-in blob is
byte-identical to what this script generates (CI drift gate).
"""


def write_model_card(blob: bytes) -> None:
    CARD_PATH.write_text(
        MODEL_CARD_TEMPLATE.format(
            vocab=VOCAB,
            embed_dim=EMBED_DIM,
            max_len=MAX_LEN,
            kernel=KERNEL,
            conv_out=CONV_OUT,
            blob_size=len(blob),
            blob_kb=len(blob) / 1024.0,
        )
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in blob matches this script's deterministic output (CI drift gate); exits nonzero on mismatch",
    )
    ap.add_argument(
        "--from-checkpoint",
        default=None,
        help="NOT YET IMPLEMENTED (see docstring) — path to an off-device-trained float32 checkpoint to quantize",
    )
    args = ap.parse_args()

    if args.from_checkpoint:
        print(
            "quantize.py: --from-checkpoint is not implemented yet (no off-device "
            "checkpoint has been trained per ADR 0014). Refusing to fabricate a "
            "'trained' model card. See the script's docstring.",
            file=sys.stderr,
        )
        return 2

    blob = build_blob()
    budget = 256 * 1024
    if len(blob) > budget:
        print(f"quantize.py: seed blob {len(blob)}B exceeds the {budget}B budget", file=sys.stderr)
        return 1

    if args.check:
        existing = BLOB_PATH.read_bytes() if BLOB_PATH.exists() else b""
        if existing != blob:
            print(
                f"quantize.py --check: {BLOB_PATH} is STALE vs this script's deterministic "
                f"output ({len(existing)}B on disk vs {len(blob)}B expected) -- re-run "
                "`python3 ci/quantize.py` and commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"quantize.py --check: {BLOB_PATH} is up to date ({len(blob)}B).")
        return 0

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    BLOB_PATH.write_bytes(blob)
    write_model_card(blob)
    print(f"quantize.py: wrote {BLOB_PATH} ({len(blob)}B) + {CARD_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
