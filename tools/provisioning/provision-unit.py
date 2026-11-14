#!/usr/bin/env python3
"""provision-unit — HookProbe OS per-unit factory provisioning (heqk Phase 7). Linux bench station, stdlib only.

  provision-unit.py run --image IMG --out DIR --ca-dir CA [--console DEV --relay "--backend nano --dev auto"]
  provision-unit.py run --resume-unit <unit-id> --out DIR ...        # continue an interrupted unit
  provision-unit.py reset-verify --resume-unit <unit-id> --out DIR (--console DEV | --verify-serial-log LOG)
  provision-unit.py otp --i-understand-otp-is-irreversible --otp-approval-file FILE   # GATE ONLY, never programs

One unit per run: flash -> serial boot capture -> parse identity + setup credential -> owner key -> MC TLS cert ->
patch OWNER.TXT/MCTLS.CRT -> verify boot -> label -> self-test -> signed-off record. The passphrase and owner key
live only in the label/owner-card files and a mode-0600 secrets file; the general log and record never contain them.
See tools/provisioning/README.md.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hqprov import otp, pipeline, serialparse  # noqa: E402


def common(p):
    p.add_argument("--out", required=True, help="station output dir; one sub-directory per unit")
    p.add_argument("--resume-unit", help="unit id (Wi-Fi MAC, no colons) of an existing work dir")


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="provision one unit")
    common(r)
    r.add_argument("--image", required=True, help="factory disk image (os/build/make-cm5-heqk-disk.sh); its .json "
                   "manifest gives the OWNER.TXT/MCTLS.CRT patch offsets")
    r.add_argument("--image-manifest", help="default: <image>.json")
    r.add_argument("--skip-flash", action="store_true", help="the unit is already flashed with --image")
    r.add_argument("--confirm-erase", action="store_true", help="pass --confirm-erase to flash-image.sh (non-interactive)")
    r.add_argument("--backup", help="flash-image.sh --backup FILE")
    r.add_argument("--console", help="serial console device, e.g. /dev/serial/by-id/usb-FTDI_...  (115200 8N1)")
    r.add_argument("--relay", help='cm5-relay.py args, e.g. "--backend nano --dev auto" (else operator prompts)')
    r.add_argument("--serial-log", help="replay a recorded boot-1 log instead of capturing")
    r.add_argument("--verify-serial-log", help="replay a recorded post-claim boot log instead of capturing")
    r.add_argument("--delete-input-logs", action="store_true",
                   help="unlink --serial-log/--verify-serial-log after use (raw captures contain the passphrase)")
    r.add_argument("--boot-timeout", type=int, default=240)
    r.add_argument("--non-interactive", action="store_true")
    r.add_argument("--patch-target", default="auto",
                   help="'auto' (rpiboot mass-storage disk by-id) or an image file (dry run); never a host disk")
    r.add_argument("--unit-id", help="override the unit directory name (default: Wi-Fi MAC)")
    r.add_argument("--ca-dir", help="owner CA directory for mctls-provision.py (created on first use, name-constrained)")
    r.add_argument("--tls-name", action="append", help="DNS SAN for the MC certificate (default heqk.local)")
    r.add_argument("--tls-ip", action="append", help="IP SAN (default 10.99.0.1, the setup-AP address). Add the management address here too "
                   "(give it a DHCP reservation): the owner CA is name-constrained to the names/IPs it is created with, "
                   "so an address learnt later shows a name mismatch (LAN assessment L-02) until the unit is re-certified")
    r.add_argument("--skip-tls", action="store_true", help="do not certify the TLS key (HTTPS stays off)")
    r.add_argument("--model", default="HookProbe OS appliance (CM5)")
    r.add_argument("--operator", default=os.environ.get("USER", "unknown"))
    r.add_argument("--mc-url", help="http://10.99.0.1/ : also sign in over the network (station must be on the unit's Wi-Fi)")
    r.add_argument("--run-mc-e2e", action="store_true", help="also run os/kernel/tools/mc-e2e-metal.sh --no-browser")
    r.add_argument("--sign-key", help="private key (PEM, openssl pkeyutl-capable e.g. Ed25519) to sign record.json")

    v = sub.add_parser("reset-verify", help="after a factory reset: the setup credential must equal the label value")
    common(v)
    v.add_argument("--console")
    v.add_argument("--relay")
    v.add_argument("--verify-serial-log")
    v.add_argument("--delete-input-logs", action="store_true")
    v.add_argument("--boot-timeout", type=int, default=240)
    v.add_argument("--non-interactive", action="store_true")

    o = sub.add_parser("otp", help="OTP secret programming GATE (irreversible; refusal path only in this tool)")
    o.add_argument(otp.FLAG, dest="otp_flag", action="store_true")
    o.add_argument("--otp-approval-file")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        if a.cmd == "otp":
            otp.program(a.otp_flag, a.otp_approval_file)
            return 0
        if a.cmd == "reset-verify":
            if not a.resume_unit:
                sys.exit("reset-verify needs --resume-unit")
            return pipeline.reset_verify(a)
        a.image_manifest = a.image_manifest or a.image + ".json"
        if not a.skip_tls and not a.ca_dir:
            sys.exit("--ca-dir is required (or --skip-tls)")
        if not a.resume_unit:
            pipeline.need_tools(a)
        return pipeline.run(a)
    except (otp.OtpRefused, otp.OtpBackendNotWired) as e:
        print(f"OTP: {e}", file=sys.stderr)
        return 3
    except (pipeline.StepError, serialparse.ParseError) as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 2
    except pipeline.bench.BenchError as e:
        print(f"BENCH ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
