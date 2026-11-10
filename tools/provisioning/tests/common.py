import importlib.util
import unittest
import warnings
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)
FIX = os.path.join(HERE, "fixtures")
warnings.simplefilter("ignore", ResourceWarning)   # test helpers read fixtures inline
os.environ.setdefault("HQPROV_NO_PNG", "1")           # PNG conversion is slow; test_label covers it explicitly

# Fabricated values baked into the fixtures (see fixtures/README.md)
SSID, PSK, MAC = "HookProbe-Setup-7K3Q", "8x3m-q7vc-4h2d-9tzp", "02:4b:7e:19:c3:a5"
QR = f"WIFI:T:WPA;S:{SSID};P:{PSK};;"
UNIT = "024b7e19c3a5"
TLS_PUB = "042c7cd1e9f26d2b9a53334cc9961e07d453b7d8d23aa6f9a2dc294b13af115619d55c46df34e9aa84ac67dc3eb69af10e70976edac090d3f2692683e0bd8ff24f"


def load_cli():
    spec = importlib.util.spec_from_file_location("provision_unit", os.path.join(ROOT, "provision-unit.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def fixture(name):
    return os.path.join(FIX, name)


def read_fixture(name):
    return open(fixture(name), encoding="utf-8", newline="").read()


def make_image(dirpath):
    """A fake factory image: unclaimed OWNER.TXT placeholder at 0x1000, empty MCTLS.CRT at 0x2000, + manifest."""
    img = os.path.join(dirpath, "factory.img")
    buf = bytearray(0x4000)
    buf[0x1000:0x1000 + 128] = (b"HQOWN0 unclaimed".ljust(127) + b"\n")
    open(img, "wb").write(bytes(buf))
    json.dump({"owner_file": {"offset": 0x1000, "length": 128}, "mctls_file": {"offset": 0x2000, "length": 4096},
               "sha256": "x"}, open(img + ".json", "w"))
    return img


class Quiet(unittest.TestCase):
    """Base class: test helpers open fixtures inline; ResourceWarning from them is noise."""

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
