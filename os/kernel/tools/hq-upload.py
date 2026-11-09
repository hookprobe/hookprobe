#!/usr/bin/env python3
"""hq-upload — put an operator-signed data pack onto a running heqk device (ADR 0056, owner side).

  hq-upload.py --mc https://10.99.0.1 --owner-key-file KEY --type shield_block --sig BLOCK.SIG --file BLOCK.TXT [--no-activate]
  hq-upload.py --mc https://10.99.0.1 --owner-key-file KEY --status

Types: shield_block, shield_allow, ioc, rules, oui, devices. The pack must already be signed with the
operator key (policy-sign.py sign-*); this tool never signs anything and never sees a private key. The
device verifies the signature with its own loader before it activates anything.

Mission Control uses a certificate from the owner's local CA (ADR 0051): pass --ca OWNER-CA.crt to verify it,
or --insecure on a bench.
"""
import argparse, hashlib, http.cookiejar, json, ssl, sys, urllib.parse, urllib.request


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mc", required=True)
    ap.add_argument("--owner-key-file", required=True)
    ap.add_argument("--type")
    ap.add_argument("--sig")
    ap.add_argument("--file")
    ap.add_argument("--no-activate", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--ca")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=a.ca) if a.ca else ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
    key = open(a.owner_key_file).read().strip()
    mc = a.mc.rstrip("/")

    def req(path, data=None, headers=None, raw=False):
        r = urllib.request.Request(mc + path, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
        try:
            with op.open(r, timeout=30) as resp:
                body = resp.read()
                try:
                    return json.loads(body) if body else {}
                except ValueError:
                    return {"raw": body[:200].decode(errors="replace")}  # e.g. the login answer
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return json.loads(body)
            except ValueError:
                return {"ok": False, "refused": f"HTTP {e.code}"}

    req("/api/login", urllib.parse.urlencode({"token": key}).encode())
    s = req("/api/session")
    if "csrf" not in s:
        sys.exit(f"login failed: {s}")
    csrf, seq = s["csrf"], s["next_seq"]
    hdr = {"Origin": mc, "X-HQ-CSRF": csrf}
    if a.status:
        print(json.dumps(req("/api/upload"), indent=2))
        return 0
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
    for off in range(0, len(cont), step):
        c = req(f"/api/upload/chunk?id={uid}&off={off}", cont[off:off + step], {**hdr, "Content-Type": "application/octet-stream"})
        if not c.get("ok"):
            print("chunk:", json.dumps(c))
            return 1
    f = form("/api/upload/finish", id=uid)
    print("finish:", json.dumps(f))
    if not f.get("ok"):
        return 1
    if a.no_activate:
        print("abort:", json.dumps(form("/api/upload/abort", id=uid)))
        return 0
    r = form("/api/upload/activate", id=uid, owner_key=key)
    print("activate:", json.dumps(r))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
