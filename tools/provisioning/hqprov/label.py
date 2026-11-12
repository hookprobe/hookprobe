"""Label (setup credential + Wi-Fi QR) and owner-key card generation. SVG always; PNG when a converter exists.

The label carries the setup credential (ADR 0054 D1: "printed on the device label with the matching Wi-Fi QR").
The owner key (ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059)) is deliberately NOT on the label: it goes on a separate card sealed in the box, so
the Wi-Fi label alone (visible on the outside of the unit) never grants Mission Control access (ADR 0054 D4).
"""
import os
import shutil
import subprocess
from xml.sax.saxutils import escape

from . import qr as pyqr

AP_URL = "http://10.99.0.1/"        # kernel/src/main.rs:3669 — Mission Control for setup-AP clients


def qr_matrix(payload):
    """Module matrix via `qrencode` when present (text output), else the vendored encoder."""
    exe = shutil.which("qrencode")
    if exe:
        r = subprocess.run([exe, "-t", "ASCII", "-m", "0", "-l", "M", "-o", "-", payload],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            rows = [ln for ln in r.stdout.splitlines() if ln.strip()]
            # ASCII output: each module is 2 chars wide, dark = "##"
            mat = [[row[i:i + 2] == "##" for i in range(0, len(row) - 1, 2)] for row in rows]
            if mat and all(len(r) == len(mat) for r in mat):      # square, else distrust it
                return mat, "qrencode"
    return pyqr.encode(payload), "builtin"


def _qr_group(payload, x, y, size_mm):
    mat, _src = qr_matrix(payload)
    path, side = pyqr.to_svg_path(mat)
    s = size_mm / side
    return (f'<g transform="translate({x},{y}) scale({s:.5f})"><rect width="{side}" height="{side}" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></g>')


def label_svg(model, unit_id, ssid, psk, qr_payload, version=""):
    """100 x 60 mm label."""
    t = lambda s: escape(s)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100mm" height="60mm" viewBox="0 0 100 60">
<rect width="100" height="60" fill="#fff" stroke="#000" stroke-width="0.4"/>
<text x="4" y="8" font-family="sans-serif" font-size="5" font-weight="bold">HookProbe</text>
<text x="4" y="13" font-family="sans-serif" font-size="3.2">{t(model)}</text>
<text x="4" y="18" font-family="monospace" font-size="3">ID {t(unit_id)}</text>
<text x="4" y="29" font-family="sans-serif" font-size="2.6" fill="#444">Wi-Fi setup network</text>
<text x="4" y="34" font-family="monospace" font-size="3.6" font-weight="bold">{t(ssid)}</text>
<text x="4" y="41" font-family="sans-serif" font-size="2.6" fill="#444">Passphrase</text>
<text x="4" y="46.5" font-family="monospace" font-size="4.4" font-weight="bold">{t(psk)}</text>
<text x="4" y="53" font-family="sans-serif" font-size="2.2" fill="#444">Scan to join, then open {t(AP_URL)}</text>
<text x="4" y="56.5" font-family="sans-serif" font-size="2.2" fill="#444">Sign in with the owner key card in the box. Factory reset keeps this passphrase.</text>
{_qr_group(qr_payload, 60, 6, 36)}
<text x="60" y="46" font-family="monospace" font-size="1.9" fill="#444">{t(version)}</text>
</svg>
'''


def owner_card_svg(unit_id, token):
    t = lambda s: escape(s)
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="85mm" height="40mm" viewBox="0 0 85 40">
<rect width="85" height="40" fill="#fff" stroke="#000" stroke-width="0.4"/>
<text x="4" y="8" font-family="sans-serif" font-size="4.5" font-weight="bold">HookProbe owner key</text>
<text x="4" y="14" font-family="monospace" font-size="2.8">unit {t(unit_id)}</text>
<text x="4" y="25" font-family="monospace" font-size="4.6" font-weight="bold">{t(token)}</text>
<text x="4" y="32" font-family="sans-serif" font-size="2.3" fill="#444">Keep this card. It is the only copy: the device stores just a hash of it.</text>
<text x="4" y="36" font-family="sans-serif" font-size="2.3" fill="#444">Whoever holds it owns this device. Do not photograph or share.</text>
</svg>
'''


def png_converter():
    if os.environ.get("HQPROV_NO_PNG"):
        return None
    for exe, mk in (("rsvg-convert", lambda s, p: [exe, "-d", "300", "-p", "300", "-o", p, s]),
                    ("inkscape", lambda s, p: [exe, s, "-o", p, "--export-dpi=300"]),
                    ("convert", lambda s, p: [exe, "-density", "300", "-background", "white", s, p])):
        if shutil.which(exe):
            return mk
    return None


def write_label_files(outdir, model, unit_id, ssid, psk, qr_payload, token, version=""):
    """Write label.svg/.png + owner-card.svg/.png (all mode 0600: they contain secrets). Returns file list."""
    os.makedirs(outdir, exist_ok=True)
    files = []
    for name, svg in (("label", label_svg(model, unit_id, ssid, psk, qr_payload, version)),
                      ("owner-card", owner_card_svg(unit_id, token))):
        p = os.path.join(outdir, name + ".svg")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(svg)
        os.chmod(p, 0o600)
        files.append(p)
        mk = png_converter()
        if mk:
            png = os.path.join(outdir, name + ".png")
            r = subprocess.run(mk(p, png), capture_output=True)
            if r.returncode == 0 and os.path.exists(png):
                os.chmod(png, 0o600)
                files.append(png)
    return files
