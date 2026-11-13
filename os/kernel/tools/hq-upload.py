#!/usr/bin/env python3
"""hq-upload — put an operator-signed data pack onto a running heqk device (ADR 0056, owner side).

  hq-upload.py --mc https://10.99.0.1 --owner-key-file KEY --type shield_block --sig BLOCK.SIG --file BLOCK.TXT [--no-activate]
  hq-upload.py --mc https://10.99.0.1 --owner-key-file KEY --status
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --rollback wan --to-generation N   # ADR 0058 (envelope)
  hq-upload.py --mc ... --owner-key-file KEY --reboot "apply WAN"    # G49: restart so staged settings apply
  hq-upload.py --mc ... --owner-key-file KEY --enroll PROOF.TXT      # ADR 0058 D3 (policy-sign.py enroll-proof output)
  hq-upload.py --mc ... --owner-key-file KEY --sign-key OLD_K_OWN.pem --rotate ROTATE.TXT   # ADR 0058 D3 (+ envelope)
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --factory-reset "reason"   # erase owner data (envelope)
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --config-confirm "reason" [--bundle HQCFG1.BIN]
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --config-rollback "reason"
  hq-upload.py --mc ... --owner-key-file KEY [--sign-key K_OWN.pem] --hsh "config status"   # the web console
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --hsh "wifi heal-test freeze"   # BENCH builds only
  hq-upload.py --mc ... --owner-key-file KEY --sign-key K_OWN.pem --hsh "artstore tamper-test devices"   # BENCH only

R6 = D: confirm / rollback, pack activate / rollback, factory reset, owner-key rotation (and privileged hsh commands)
need an HQMGMT1 envelope signed by the enrolled owner key; the owner token (--owner-key-file) only opens the session.
This tool signs it LOCALLY with --sign-key (policy-sign.py's mgmt-sign; the private key never goes to the device),
bound to what GET /api/config's "envelope" reports (device, boot epoch, next sequence, the bundle in force). With
--bundle the digest is computed from your file and must match the device's — you confirm exactly what you staged.

Types: shield_block, shield_allow, ioc, rules, oui, devices (apply now); wan, wifi, policy, config (staged), os_image.
The pack must already be signed with the operator key (policy-sign.py sign-*); this tool never signs packs. Its
only signature is the activate envelope (--sign-key, local), bound to the type, generation and digest the device
reports at finish — checked against your own file first. The device verifies the pack with its own loader.

Mission Control uses a certificate from the HookProbe factory CA (ADR 0051): pass --ca FACTORY-CA.crt to verify it,
or --insecure on a bench.
"""
import importlib.util, os
import argparse, hashlib, http.cookiejar, json, ssl, sys, urllib.parse, urllib.request


def PS():
    """policy-sign.py as a module (the envelope builder)."""
    spec = importlib.util.spec_from_file_location("policy_sign", os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy-sign.py"))
    ps = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ps)
    return ps


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mc", required=True)
    ap.add_argument("--owner-key-file", required=True)
    ap.add_argument("--type")
    ap.add_argument("--sig")
    ap.add_argument("--file")
    ap.add_argument("--no-activate", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--rollback")
    ap.add_argument("--reboot")
    ap.add_argument("--enroll")
    ap.add_argument("--rotate")
    ap.add_argument("--sign-key")
    ap.add_argument("--config-confirm")
    ap.add_argument("--config-rollback")
    ap.add_argument("--bundle")
    ap.add_argument("--hsh")
    ap.add_argument("--to-generation", type=int)
    ap.add_argument("--factory-reset")
    ap.add_argument("--ca")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=a.ca) if a.ca else ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # ONE kept-alive connection for the whole upload (an OS image is ~2,300 chunks: a fresh TLS handshake per
    # chunk exhausted the device's HTTPS slots and the server reset the connection — bench 2026-11-10).
    import http.client, time
    u = urllib.parse.urlparse(a.mc.rstrip("/"))
    conn = [None]
    jar = {}
    key = open(a.owner_key_file).read().strip()
    mc = a.mc.rstrip("/")

    def connect():
        if u.scheme == "https":
            conn[0] = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=30)
        else:
            conn[0] = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=30)

    def req(path, data=None, headers=None, raw=False):
        for attempt in range(5):
            try:
                if conn[0] is None:
                    connect()
                h = dict(headers or {})
                if jar:
                    h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
                conn[0].request("POST" if data is not None else "GET", path, body=data, headers=h)
                r = conn[0].getresponse()
                body = r.read()
                for sc in r.headers.get_all("Set-Cookie") or []:
                    kv = sc.split(";", 1)[0]
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        if v:
                            jar[k.strip()] = v.strip()
                        else:
                            jar.pop(k.strip(), None)
                if (r.getheader("Connection") or "").lower() == "close":
                    conn[0].close()
                    conn[0] = None
                try:
                    return json.loads(body) if body else {}
                except ValueError:
                    return {"raw": body[:200].decode(errors="replace")}  # e.g. the login answer
            except (OSError, http.client.HTTPException):
                if conn[0] is not None:
                    conn[0].close()
                conn[0] = None
                time.sleep(1 + attempt)
        return {"ok": False, "refused": "connection failed"}

    req("/api/login", urllib.parse.urlencode({"token": key}).encode())
    s = req("/api/session")
    if "csrf" not in s:
        sys.exit(f"login failed: {s}")
    csrf, seq = s["csrf"], s["next_seq"]
    hdr = {"Origin": mc, "X-HQ-CSRF": csrf}
    if a.status:
        print(json.dumps(req("/api/upload"), indent=2))
        return 0

    def form1(path, **kv):
        nonlocal seq
        kv["seq"] = seq
        seq += 1
        return req(path, urllib.parse.urlencode(kv).encode(), {**hdr, "Content-Type": "application/x-www-form-urlencoded"})

    def envelope(msg, arg=0, generation=None, digest=None):
        """R6 = D: sign an HQMGMT1 envelope locally with the owner key, bound to what the device reports
        (device id, boot epoch, next sequence); generation / digest default to the bundle in force (confirm / rollback)."""
        if not a.sign_key:
            sys.exit("--sign-key (the enrolled owner key, PEM) is required for a privileged operation")
        ps = PS()
        e = req("/api/config").get("envelope") or {}
        if not e.get("owner_enrolled"):
            sys.exit(f"the device reports no enrolled owner key: {e}")
        dg = digest
        digest = bytes.fromhex(e["digest"])
        if a.bundle and msg in ("confirm", "rollback"):
            mine = hashlib.sha256(open(a.bundle, "rb").read()).digest()
            if mine != digest:
                sys.exit(f"the bundle in force ({e['digest']}) is not {a.bundle} ({mine.hex()}): refusing to sign")
        gen = int(e["generation"]) if msg in ("confirm", "rollback") else 0
        if msg not in ("confirm", "rollback"):
            digest = b"\0" * 32
        if generation is not None:
            gen = generation
        if dg is not None:
            digest = dg
        return ps.mgmt_envelope(ps.load(a.sign_key), bytes.fromhex(e["device_id"]), bytes.fromhex(e["epoch"]), int(e["next_seq"]),
                                msg, arg, gen, digest).hex()

    if a.config_confirm or a.config_rollback:
        confirm = bool(a.config_confirm)
        env = envelope("confirm" if confirm else "rollback")
        r = form1("/api/config/confirm" if confirm else "/api/config/rollback", reason=a.config_confirm or a.config_rollback,
                  permanent="true", owner_key=key, envelope=env)
        print(json.dumps(r))
        return 0 if r.get("ok") else 1
    if a.hsh is not None:
        words = a.hsh.split()
        msg = {("config", "confirm"): "confirm", ("config", "rollback"): "rollback", ("config", "stage"): "stage"}.get(tuple(words[:2]))
        body = a.hsh
        if msg:
            body += "\n" + envelope(msg, (int(words[2], 16) if len(words[2]) == 16 else int(words[2])) if msg == "stage" and len(words) > 2 else 0)
        elif tuple(words[:2]) == ("wifi", "heal-test") and len(words) > 2 and words[2] != "status":
            # BENCH builds only (kernel feature wifiheal-bench): each change is bound to its op code
            op = PS().HEAL_TEST_OP.get(words[2])
            if op is None:
                sys.exit(f"wifi heal-test: one of status, {', '.join(PS().HEAL_TEST_OP)}")
            body += "\n" + envelope("wifi-heal-test", op)
        elif tuple(words[:2]) == ("artstore", "tamper-test") and len(words) > 2:
            # BENCH builds only (kernel feature artstore-bench): the envelope is bound to the artifact type code
            tc = PS().TYPE_CODE.get(words[2])
            if tc is None or words[2] in ("config", "os_image"):
                sys.exit("artstore tamper-test: one of shield_block, shield_allow, ioc, rules, oui, devices, wan, wifi, policy")
            body += "\n" + envelope("artstore-tamper-test", tc)
        conn_h = {**hdr, "Content-Type": "text/plain"}
        if conn[0] is None:
            connect()
        # an owner write like the others: the session seq rides in ?seq= (rate limited, replay-checked)
        conn[0].request("POST", f"/api/hsh?seq={seq}", body=body.encode(), headers={**conn_h, "Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())})
        print(conn[0].getresponse().read().decode(errors="replace"), end="")
        return 0
    if a.rollback or a.reboot or a.enroll or a.rotate or a.factory_reset:
        if a.rollback:
            if a.to_generation is None:
                sys.exit("--to-generation N (the generation to roll back to) is required: the envelope binds it")
            env = envelope("pack-rollback", PS().TYPE_CODE[a.rollback], a.to_generation)
            r = form1("/api/upload/rollback", type=a.rollback, envelope=env)
        elif a.factory_reset:
            r = form1("/api/factory-reset", confirm="ERASE", reason=a.factory_reset, permanent="true", envelope=envelope("factory-reset"))
        elif a.reboot:
            r = form1("/api/reboot", reason=a.reboot, permanent="true", owner_key=key)
        elif a.rotate:
            kv = dict(l.split("=", 1) for l in open(a.rotate).read().split() if "=" in l)
            cur = req("/api/anchor").get("owner_key")
            if not cur:
                sys.exit("the device reports no enrolled owner key to rotate")
            ps = PS()
            env = envelope("rotate", ps.fp8(bytes.fromhex(cur)), int(kv["generation"]), hashlib.sha256(bytes.fromhex(kv["public_key"])).digest())
            r = form1("/api/anchor/rotate", envelope=env, **kv)
        else:
            kv = dict(l.split("=", 1) for l in open(a.enroll).read().split() if "=" in l)
            r = form1("/api/anchor/enroll", owner_key=key, **kv)
        print(json.dumps(r))
        return 0 if r.get("ok") else 1
    if a.type == "os_image":
        # An OS image carries its own hybrid signature: the container is the signed heqk8.img itself.
        if not a.file:
            sys.exit("--file (the signed heqk8.img) is required")
        cont = open(a.file, "rb").read()
    else:
        if not (a.type and a.sig and a.file):
            sys.exit("--type, --sig and --file are required")
        sig = open(a.sig, "rb").read()
        if len(sig) != 512:
            sys.exit("a pack signature file is exactly 512 bytes")
        cont = sig + open(a.file, "rb").read()

    def form(path, **kv):
        nonlocal seq
        kv["seq"] = seq
        seq += 1
        return req(path, urllib.parse.urlencode(kv).encode(), {**hdr, "Content-Type": "application/x-www-form-urlencoded"})

    b = form("/api/upload/begin", type=a.type, size=len(cont), sha256=hashlib.sha256(cont).hexdigest(), owner_key=key)
    print("begin:", json.dumps(b))
    if not b.get("ok"):
        return 1
    uid, step = b["id"], int(b["chunk_max"])
    off = 0
    while off < len(cont):
        c = req(f"/api/upload/chunk?id={uid}&off={off}", cont[off:off + step], {**hdr, "Content-Type": "application/octet-stream"})
        if c.get("ok"):
            off += len(cont[off:off + step])
            continue
        # a dropped connection may have delivered the chunk anyway: resume at what the device has
        st = req("/api/upload").get("in_flight") or {}
        if st.get("id") == f"{uid:016x}" if isinstance(uid, int) else st.get("id") == uid:
            got = int(st.get("received", -1))
            if got > off:
                off = got
                continue
        print("chunk:", json.dumps(c))
        return 1
    f = form("/api/upload/finish", id=uid)
    print("finish:", json.dumps(f))
    if not f.get("ok"):
        return 1
    if a.no_activate:
        print("abort:", json.dumps(form("/api/upload/abort", id=uid)))
        return 0
    # R6 = D: the activate envelope binds the type, generation and content digest the device reports at finish —
    # checked against this tool's own file first (the digest of the pack body, or the image for os_image)
    body_dg = hashlib.sha256(cont if a.type == "os_image" else open(a.file, "rb").read()).hexdigest()
    if a.type != "os_image" and f.get("digest") != body_dg:
        sys.exit(f"the device staged digest {f.get('digest')}, your file is {body_dg}: refusing to sign")
    env = envelope("activate", PS().TYPE_CODE[a.type], int(f["generation"]), bytes.fromhex(f["digest"]))
    r = form("/api/upload/activate", id=uid, envelope=env)
    print("activate:", json.dumps(r))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
