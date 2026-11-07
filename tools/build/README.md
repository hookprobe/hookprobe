# tools/build

- The image build engine itself is [`os/build/`](../../os/build/).
- One-command validation: [`os/kernel/validate.sh`](../../os/kernel/validate.sh) (QEMU) and
  [`os/kernel/tools/mc-e2e.sh`](../../os/kernel/tools/mc-e2e.sh) (browser end to end).
- Git hook: [`git-hooks/pre-push`](git-hooks/pre-push) blocks secrets before a push.
  Install it once per clone: `ln -sf ../../tools/build/git-hooks/pre-push .git/hooks/pre-push`.
