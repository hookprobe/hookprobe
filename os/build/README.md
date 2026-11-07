# os/build — the image build engine

Turns the heqk workspace + the Mission Control UI into **signed** boot artifacts.

| Script | Produces |
|---|---|
| [`make-cm5-heqk-image.sh`](make-cm5-heqk-image.sh) | signed `heqk8.img` (hboot-wrapped kernel) + `config.txt` / `tryboot.txt` |
| [`make-cm5-heqk-disk.sh`](make-cm5-heqk-disk.sh) | a whole **factory disk image** (MBR, FAT32 A/B boot set, heqk DataVolume) + `.sha256`, `.json` manifest and a mode-600 `.owner-key` |
| [`gen-heqk-dev-keys.sh`](gen-heqk-dev-keys.sh) | a DEV boot-signing keydir (bench only; never for release) |
| [`heqk-boot-key-check.sh`](heqk-boot-key-check.sh) | release-blocking gate: refuses a release image that carries DEV keys ([fingerprints](heqk-dev-key-fingerprints.txt)) |
| [`heqk-sign/`](heqk-sign/) | the in-tree signer: Ed25519 + SLH-DSA-128s boot signatures |

```sh
# dev keys (once), then a production Mission Control factory image with no devicetree
os/build/gen-heqk-dev-keys.sh
HEQK_KEYDIR=os/build/.heqk-dev-keys FEATURES=prod-mc os/build/make-cm5-heqk-disk.sh --zero-linux --owner-token auto
# output: os/build/generated/cm5-heqk/
```

Platform profiles: [`appliance/`](../../appliance/). Flashing: [`tools/flash/`](../../tools/flash/).
