"""The per-unit station flow. One unit per run; every step records its result in state.json and is skipped on
resume when already ok and its artifacts still exist.

  flash -> capture1 -> identity -> owner -> tls -> patch -> capture2(verify) -> label -> selftest -> record
"""
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

from . import bench, label, owner, selftest, serialparse as sp, store

TOOL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIRST_BOOT_MARKERS = [r"\[WIFI\] setup AP ", r"\[MC-TLS\] device TLS key", r"\[WIFI\] per-device MAC"]
VERIFY_MARKERS = [r"\[P11-AP2\] PASS", r"\[AP-MC\] owner:", r"\[MC-TLS\] "]


class StepError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tool_commit():
    try:
        top = subprocess.run(["git", "-C", TOOL_DIR, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "-C", TOOL_DIR, "status", "--porcelain", "--", TOOL_DIR],
                               capture_output=True, text=True, timeout=10)
        if top.returncode == 0:
            return top.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def need_tools(args):
    miss = []
    if not args.skip_tls and not shutil.which("openssl"):
        miss.append("openssl (needed by mctls-provision.py)")
    if miss:
        raise StepError("missing prerequisites: " + "; ".join(miss) + ". Install them, or pass --skip-tls.")


def read_boot_text(path):
    with open(path, "r", errors="replace") as f:
        return f.read()


def get_boot_text(args, which, until, log):
    """Replay a recorded log when given, else capture from the console (relay-cycled when --relay)."""
    logfile = args.serial_log if which == 1 else args.verify_serial_log
    if logfile:
        log(f"boot {which}: using recorded serial log {logfile} (a RAW capture: it contains the setup passphrase)")
        text = read_boot_text(logfile)
        if getattr(args, "delete_input_logs", False):
            os.unlink(logfile)
            log(f"boot {which}: deleted the raw input log {logfile} (--delete-input-logs)")
        return text
    if not args.console:
        raise StepError(f"boot {which}: need --console DEV (or a recorded --{'serial' if which == 1 else 'verify-serial'}-log)")
    fd = bench.open_console(args.console)

    def start():
        if args.relay:
            bench.relay(args.relay, "boot")
        else:
            bench.prompt("remove the nRPIBOOT jumper if fitted, then power-cycle the unit", args.non_interactive)
    # A unit with no SRK never prints the setup line: the capture times out and the parser gives the diagnosis.
    text, _ok = bench.capture(fd, until, args.boot_timeout, on_start=start)
    os.close(fd)
    return text


# ------------------------------------------------------------------------------------------------
def step_flash(args, pend):
    if args.skip_flash:
        pend.log("flash: skipped (--skip-flash)")
        return
    if args.relay:
        bench.relay(args.relay, "rpiboot")
    pend.log(f"flash: {args.image} (sha256 {sha256_file(args.image)[:16]}...)")
    bench.flash(args.image, confirm_erase=args.confirm_erase, backup=args.backup)


def step_capture_identity(args, pend):
    """Boot 1: parse identity + setup credential. Returns (Unit, parsed)."""
    raw = get_boot_text(args, 1, FIRST_BOOT_MARKERS, pend.log)
    p = sp.parse(raw)
    try:
        sp.require_identity(p)
    except sp.ParseError as e:
        raise StepError(f"first boot rejected: {e}")
    uid = args.unit_id or sp.unit_id(p)
    udir = os.path.join(args.out, uid)
    if os.path.exists(os.path.join(udir, "state.json")):
        # Same unit provisioned again (a re-flash / factory reset): never mix with the old state or silently skip
        # the patch. The previous work dir (and its secrets) is kept aside, mode 0700.
        prev = f"{udir}.prev-{store.now().replace(':', '')}"
        os.rename(udir, prev)
        pend.log(f"unit {uid} was provisioned before: previous work dir kept as {os.path.basename(prev)}")
    unit = store.Unit(udir)
    # Secrets first, THEN any text is written, so the redactor knows them.
    unit.set_secret("setup_psk", p["setup_psk"])
    unit.set_secret("qr_payload", p["qr_payload"])
    unit.save_redacted_log("boot-1.redacted.log", sp.clean(raw))
    ident = {k: v for k, v in p.items() if k not in ("setup_psk", "qr_payload")}
    ident["unit_id"] = uid
    ident["captured_at"] = store.now()
    unit.save_public("identity.json", ident)
    if os.path.exists(pend.p("provision.log")):                  # carry the pre-identity log over
        with open(pend.p("provision.log")) as f, open(unit.p("provision.log"), "a") as g:
            g.write(f.read())
    unit.mark("capture1", "ok", f"markers: {','.join(p['markers_seen'])}")
    unit.mark("identity", "ok", f"unit {uid} mac {p['wifi_mac']} ssid {p['setup_ssid']}")
    return unit, p


def step_owner(args, unit):
    """Mint the owner key (ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059)) once; keep it only in the 0600 secrets file."""
    s = unit.secrets()
    if "owner_token" not in s:
        tok = owner.mint_token()
        unit.set_secret("owner_token", tok)
        unit.set_secret("owner_file_hex", owner.owner_file_bytes(tok).hex())
    unit.mark("owner", "ok", "owner key minted (verifier staged); token held only in secrets.json + owner card")


def step_tls(args, unit, ident):
    if args.skip_tls:
        unit.mark("tls", "skipped", "--skip-tls: HTTPS stays off until a certificate is provisioned")
        return
    crt = unit.p("MCTLS.CRT")
    if not (unit.done("tls") and os.path.exists(crt)):
        need_tools(args)
        cmd = [sys.executable, bench.MCTLS_PROVISION, "--ca-dir", args.ca_dir, "--pub", ident["tls_pub"], "--out", crt]
        for n in args.tls_name or ["heqk.local"]:
            cmd += ["--name", n]
        for i in args.tls_ip or ["10.99.0.1"]:
            cmd += ["--ip", i]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise StepError("mctls-provision.py failed: " + (r.stdout + r.stderr).strip())
        unit.log("tls: " + r.stdout.strip())
    unit.mark("tls", "ok", f"MCTLS.CRT sha256 {sha256_file(crt)[:16]}...")


def _resolve_patch_target(args, log):
    if args.patch_target != "auto":
        return args.patch_target
    if args.relay:
        bench.relay(args.relay, "rpiboot")
        bench.run_rpiboot()
    else:
        bench.prompt("fit the nRPIBOOT jumper and power-cycle the unit (rpiboot mode); press Enter to run rpiboot",
                     args.non_interactive)
        bench.run_rpiboot()
    d = bench.find_rpiboot_disk()
    if not d:
        raise StepError("no Raspberry Pi mass-storage disk appeared after rpiboot")
    log(f"patch target: {d}")
    return d


def step_patch(args, unit):
    if not args.image_manifest or not os.path.exists(args.image_manifest):
        raise StepError(f"image manifest not found ({args.image_manifest}): it records the in-place patch offsets")
    manifest = owner.load_manifest(args.image_manifest)
    obytes = bytes.fromhex(unit.secrets()["owner_file_hex"])
    with open(unit.p("MCTLS.CRT"), "rb") as f:
        mbytes = f.read()
    target = _resolve_patch_target(args, unit.log)
    try:
        done = owner.patch_boot_files(target, manifest, obytes, mbytes)
    except owner.PatchError as e:
        raise StepError(f"patch refused: {e}")
    unit.mark("patch", "ok", json.dumps(done))


def step_patch_owner_only(args, unit):
    manifest = owner.load_manifest(args.image_manifest)
    obytes = bytes.fromhex(unit.secrets()["owner_file_hex"])
    target = _resolve_patch_target(args, unit.log)
    fd = os.open(target, os.O_RDWR)
    try:
        owner.check_target(target)
        cur = os.pread(fd, owner.OWNER_FILE_LEN, manifest["owner_file"]["offset"])
        if cur == obytes:
            done = "already-set"
        elif cur.startswith(b"HQOWN0"):
            os.pwrite(fd, obytes, manifest["owner_file"]["offset"])
            os.fsync(fd)
            if os.pread(fd, owner.OWNER_FILE_LEN, manifest["owner_file"]["offset"]) != obytes:
                raise StepError("owner read-back failed")
            done = "written"
        else:
            raise StepError("OWNER.TXT is not the unclaimed placeholder and not ours; re-flash first")
    finally:
        os.close(fd)
    unit.mark("patch", "ok", json.dumps({"owner": done, "mctls": "skipped"}))


def step_verify_boot(args, unit):
    raw = get_boot_text(args, 2, VERIFY_MARKERS, unit.log)
    p = sp.parse(raw)
    s = unit.secrets()
    ident = store.jload(unit.p("identity.json"))
    p["setup_same"] = bool(p.get("setup_psk")) and p.get("setup_psk") == s["setup_psk"] and p.get("setup_ssid") == ident["setup_ssid"]
    p["fail_markers"] = [rx.pattern for rx in selftest.FAIL_RE if rx.search(sp.clean(raw))]
    unit.save_redacted_log("boot-2.redacted.log", sp.clean(raw))
    for k in ("setup_psk", "qr_payload"):
        p.pop(k, None)
    unit.save_public("boot2.json", p)
    return p


def step_label(args, unit, ident):
    s = unit.secrets()
    files = label.write_label_files(unit.dir, args.model, ident["unit_id"], ident["setup_ssid"], s["setup_psk"],
                                    s["qr_payload"], s["owner_token"], version=f"fw {tool_commit()[:8]}")
    qr_src = label.qr_matrix(s["qr_payload"])[1]
    unit.mark("label", "ok", f"{', '.join(os.path.basename(f) for f in files)} (QR via {qr_src})")


def step_selftest(args, unit, ident, second):
    results = selftest.check_boot(ident, second)
    if args.skip_tls:
        results = [r for r in results if not r["name"].startswith("HTTPS ready")]
    if args.mc_url:
        results += selftest.check_http(args.mc_url, unit.secrets()["owner_token"])
    if args.run_mc_e2e:
        if not args.mc_url:
            raise StepError("--run-mc-e2e needs --mc-url (its host is the device address)")
        keyf = unit.p("owner.key.tmp")
        store.write_private(keyf, unit.secrets()["owner_token"] + "\n")
        try:
            import urllib.parse
            results += selftest.run_mc_e2e(bench.MC_E2E_METAL, urllib.parse.urlparse(args.mc_url).hostname, keyf)
        finally:
            os.unlink(keyf)
    ok = all(r["ok"] for r in results)
    unit.save_public("selftest.json", {"at": store.now(), "ok": ok, "results": results})
    for r in results:
        unit.log(f"selftest {'ok  ' if r['ok'] else 'FAIL'} {r['name']} {r['detail']}")
    unit.mark("selftest", "ok" if ok else "failed", f"{sum(r['ok'] for r in results)}/{len(results)} checks")
    return ok


def sign_record(path, key):
    """Detached Ed25519 (or any openssl pkeyutl-capable key) signature over the exact record bytes."""
    if not shutil.which("openssl"):
        raise StepError("--sign-key needs the openssl CLI")
    sig = path + ".sig"
    r = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", path, "-out", sig],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise StepError("signing failed: " + r.stderr.strip())
    return sig


def step_record(args, unit, ident, selftest_ok):
    rec = {
        "schema": "hookprobe-factory-record/1",
        "recorded_at": store.now(),
        "operator": args.operator,
        "model": args.model,
        "tool_git_commit": tool_commit(),
        "image": {"path": os.path.basename(args.image), "sha256": sha256_file(args.image) if os.path.exists(args.image) else None},
        "unit_id": ident["unit_id"],
        "identity": {k: ident.get(k) for k in ("wifi_mac", "setup_ssid", "tls_pub", "netcp_pk", "netcp_fp8")},
        "steps": unit.state["steps"],
        "selftest_ok": selftest_ok,
        "shippable": bool(selftest_ok and all(v["status"] in ("ok", "skipped") for v in unit.state["steps"].values())),
        "secrets_note": "setup passphrase and owner key are NOT in this record; see label.svg / owner-card.svg",
    }
    body = json.dumps(rec, indent=2, sort_keys=True)
    assert not any(sec in body for sec in unit.secret_strings()), "secret leaked into the record"
    path = unit.p("record.json")
    with open(path, "w") as f:
        f.write(body + "\n")
    if args.sign_key:
        sig = sign_record(path, args.sign_key)
        rec["signature_file"] = os.path.basename(sig)
        unit.log(f"record signed: {sig}")
    else:
        unit.log("record is UNSIGNED (no --sign-key); it carries no signature")
    unit.mark("record", "ok", f"shippable={rec['shippable']}")
    return rec


# ------------------------------------------------------------------------------------------------
def run(args):
    os.makedirs(args.out, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    resume = bool(args.resume_unit)
    if resume:
        unit = store.Unit(os.path.join(args.out, args.resume_unit))
        if not unit.done("identity") or not os.path.exists(unit.p("identity.json")):
            raise StepError(f"unit {args.resume_unit} has no completed identity step: start a fresh run instead")
        ident = store.jload(unit.p("identity.json"))
        unit.log(f"resuming unit {args.resume_unit}")
    else:
        pend = store.Unit(os.path.join(args.out, f"_pending-{ts}"))
        step_flash(args, pend)
        unit, p = step_capture_identity(args, pend)
        shutil.rmtree(pend.dir, ignore_errors=True)
        ident = store.jload(unit.p("identity.json"))
        unit.mark("flash", "skipped" if args.skip_flash else "ok", args.image)
    unit.log(f"unit {ident['unit_id']}: Wi-Fi MAC {ident['wifi_mac']}, setup SSID {ident['setup_ssid']}")

    if not unit.done("owner"):
        step_owner(args, unit)
    if not unit.done("tls"):
        step_tls(args, unit, ident)
    if not unit.done("patch"):
        (step_patch_owner_only if args.skip_tls else step_patch)(args, unit)
    second = None
    if not unit.done("capture2") or not os.path.exists(unit.p("boot2.json")):
        second = step_verify_boot(args, unit)
        unit.mark("capture2", "ok", f"markers: {','.join(second['markers_seen'])}")
    else:
        second = store.jload(unit.p("boot2.json"))          # resumed after a captured verify boot
    if not unit.done("label"):
        step_label(args, unit, ident)
    ok = True
    if not unit.done("selftest"):
        ok = step_selftest(args, unit, ident, second)
    else:
        ok = unit.state["steps"]["selftest"]["status"] == "ok"
    rec = step_record(args, unit, ident, ok)
    unit.log("RESULT: " + ("SHIPPABLE" if rec["shippable"] else "NOT SHIPPABLE (see selftest.json / provision.log)"))
    return 0 if rec["shippable"] else 1


# ------------------------------------------------------------------------------------------------
UNIVERSAL_DENYLIST = ("password", "hookprobe", "admin", "12345678", "00000000", "0000-0000-0000-0000",
                      "heqk-ap", "heqk", "changeme")


def reset_verify(args):
    """After a factory reset (see README): the setup credential must re-derive to the SAME label value
    (ADR 0054 D1), come from the per-device derivation (never WIFI.TXT/build env), differ from every other unit
    in this work area, and no universal password may appear. Returns 0/1."""
    unit = store.Unit(os.path.join(args.out, args.resume_unit))
    s = unit.secrets()
    if "setup_psk" not in s:
        raise StepError("this unit has no stored label credential to compare against")
    ident = store.jload(unit.p("identity.json"))
    raw = get_boot_text(args, 2, VERIFY_MARKERS + [r"\[WIFI\] setup AP "], unit.log)
    p = sp.parse(raw)
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    add("setup line present", "setup_psk" in p, "no setup AP marker after reset" if "setup_psk" not in p else "")
    same = p.get("setup_psk") == s["setup_psk"] and p.get("setup_ssid") == ident["setup_ssid"]
    add("setup credential re-derives to the SAME label value", same)
    add("per-device MAC unchanged", p.get("wifi_mac") == ident["wifi_mac"])
    add("PSK source is the per-device derivation", p.get("psk_source") in (None, "the per-device setup credential"),
        p.get("psk_source", "ap2 line absent"))
    psk = p.get("setup_psk", "")
    add("no universal/default password", not any(d in psk.lower() for d in UNIVERSAL_DENYLIST) and bool(sp.PSK_RE.match(psk)))
    clash = []
    for d in os.listdir(args.out):
        sp_path = os.path.join(args.out, d, "secrets.json")
        if not d.startswith(args.resume_unit) and not d.startswith("_pending") and os.path.exists(sp_path):
            try:
                if store.jload(sp_path).get("setup_psk") == psk and psk:
                    clash.append(d)
            except ValueError:
                pass
    add("passphrase unique among provisioned units", not clash, "shared with " + ",".join(clash) if clash else "")
    add("no shared/default-key refusal marker", not p.get("no_ap") and not p.get("tls_off_nosrk"))
    ok = all(c["ok"] for c in checks)
    unit.save_redacted_log("boot-reset.redacted.log", sp.clean(raw))
    unit.save_public("reset-verify.json", {"at": store.now(), "ok": ok, "owner_state": p.get("owner"), "checks": checks})
    for c in checks:
        unit.log(f"reset-verify {'ok  ' if c['ok'] else 'FAIL'} {c['name']} {c['detail']}")
    unit.mark("reset_verify", "ok" if ok else "failed", f"owner after reset: {p.get('owner', 'unknown')}")
    return 0 if ok else 1
