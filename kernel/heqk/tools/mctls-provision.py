#!/usr/bin/env python3
"""mctls-provision — certify a heqk device's TLS key with the owner's local CA (ADR 0051 D2/D3).

The device derives its P-256 key from its SRK and prints only the PUBLIC point:
    [MC-TLS] device TLS key (P-256, SRK-derived) pub=04…
This tool turns that point into a certificate signed by the owner CA and writes the fixed 4 KiB
MCTLS.CRT the device reads from its boot partition. The CA private key never goes to the device.

  mctls-provision.py --ca-dir DIR --pub 04… --name heqk.local [--ip 10.200.0.6 …] --out MCTLS.CRT

The CA is created on first use in DIR (ca.key mode 600, ca.pem) with X.509 NAME CONSTRAINTS: it can only
certify the names/addresses given at creation (--permit-dns / --permit-ip), so a leaked CA key cannot mint
certificates for other sites. Install DIR/ca.pem once in the browser/OS trust store.
"""
import argparse, os, struct, subprocess, sys, tempfile

SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
MAGIC = b"HQCRT1\0\0"
FILE_LEN = 4096


def run(*a):
    r = subprocess.run(a, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        sys.exit(f"openssl failed: {' '.join(a[:3])} …\n{r.stderr.strip()}")


def ensure_ca(d, dns, ips):
    key, pem = os.path.join(d, "ca.key"), os.path.join(d, "ca.pem")
    if os.path.exists(key) and os.path.exists(pem):
        return key, pem
    os.makedirs(d, exist_ok=True)
    perm = [f"permitted;DNS:{n}" for n in dns] + [f"permitted;IP:{ip}" for ip in ips]
    ext = os.path.join(d, "ca.cnf")
    with open(ext, "w") as f:
        f.write("[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\n" + ("nameConstraints=critical," + ",".join(perm) + "\n" if perm else ""))
    old = os.umask(0o077)
    try:
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    finally:
        os.umask(old)
    run("openssl", "req", "-x509", "-new", "-key", key, "-sha256", "-days", "3650", "-subj",
        "/CN=HookProbe owner CA (heqk)", "-config", ext, "-extensions", "v3", "-out", pem)
    return key, pem


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ca-dir", required=True)
    ap.add_argument("--pub", required=True, help="the 65-byte SEC1 point printed by the device (hex, 04…)")
    ap.add_argument("--name", action="append", default=[], help="DNS name for the device certificate")
    ap.add_argument("--ip", action="append", default=[], help="IP address for the device certificate")
    ap.add_argument("--permit-dns", action="append", default=[], help="CA name constraint (creation only)")
    ap.add_argument("--permit-ip", action="append", default=[], help="CA constraint, e.g. 10.0.0.0/255.0.0.0")
    ap.add_argument("--days", type=int, default=397)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    pt = bytes.fromhex(a.pub.strip())
    if len(pt) != 65 or pt[0] != 4:
        sys.exit("--pub must be the 65-byte uncompressed P-256 point (starts with 04)")
    # Default CA constraints: the device names + private address space only (RFC 1918 + link-local) — the CA
    # can certify any LAN address a HookProbe device uses (port, AP, management VLAN) but never a public site.
    permit_ip = a.permit_ip or ["10.0.0.0/255.0.0.0", "172.16.0.0/255.240.0.0", "192.168.0.0/255.255.0.0", "169.254.0.0/255.255.0.0"]
    key, pem = ensure_ca(a.ca_dir, a.permit_dns or a.name or ["heqk.local"], permit_ip)
    with tempfile.TemporaryDirectory() as t:
        pub = os.path.join(t, "dev.pub.der")
        open(pub, "wb").write(SPKI_P256_PREFIX + pt)
        pubpem = os.path.join(t, "dev.pub.pem")
        run("openssl", "pkey", "-pubin", "-inform", "DER", "-in", pub, "-out", pubpem)
        # A throwaway key only to satisfy `req`; -force_pubkey puts the DEVICE key in the certificate.
        tmpk = os.path.join(t, "tmp.key")
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", tmpk)
        csr = os.path.join(t, "dev.csr")
        cn = a.name[0] if a.name else "heqk"
        run("openssl", "req", "-new", "-key", tmpk, "-subj", f"/CN={cn}", "-out", csr)
        ext = os.path.join(t, "leaf.ext")
        san = ",".join([f"DNS:{n}" for n in a.name] + [f"IP:{i}" for i in a.ip])
        with open(ext, "w") as f:
            f.write("basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n"
                    "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n"
                    + (f"subjectAltName={san}\n" if san else ""))
        crt = os.path.join(t, "dev.der")
        run("openssl", "x509", "-req", "-in", csr, "-CA", pem, "-CAkey", key, "-CAcreateserial", "-sha256",
            "-days", str(a.days), "-force_pubkey", pubpem, "-extfile", ext, "-outform", "DER", "-out", crt)
        leaf = open(crt, "rb").read()
    body = MAGIC + struct.pack("<H", 1) + struct.pack("<H", len(leaf)) + leaf
    if len(body) > FILE_LEN:
        sys.exit("certificate too large for MCTLS.CRT")
    open(a.out, "wb").write(body.ljust(FILE_LEN, b"\0"))
    print(f"MCTLS.CRT written ({len(leaf)} B leaf, CA {pem})")


if __name__ == "__main__":
    main()
