import unittest

from common import QR, Quiet
from hqprov import qr


def decode(mat, version):
    """Decoder for our own output: format info -> mask -> codewords -> RS syndrome check -> payload."""
    size, fn = qr.function_mask(version)
    assert len(mat) == size
    bits = 0
    for i in range(6):
        bits |= mat[i][8] << i
    bits |= mat[7][8] << 6
    bits |= mat[8][8] << 7
    bits |= mat[8][7] << 8
    for i in range(9, 15):
        bits |= mat[8][14 - i] << i
    mask = None
    for m in range(8):
        if qr.format_bits(m) == bits:
            mask = m
    assert mask is not None, "format info does not decode"
    b2 = 0                                                    # the second copy must agree
    for i in range(8):
        b2 |= mat[8][size - 1 - i] << i
    for i in range(8, 15):
        b2 |= mat[size - 15 + i][8] << i
    assert b2 == bits
    f = qr.mask_fn(mask)
    stream = []
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                y = size - 1 - vert if ((right + 1) & 2) == 0 else vert
                if not fn[y][x]:
                    stream.append(int(mat[y][x] ^ f(x, y)))
        right -= 2
    cw = [int("".join(map(str, stream[i:i + 8])), 2) for i in range(0, len(stream) - 7, 8)]
    ec, nb, dc = qr._ECC_M[version]
    cw = cw[:nb * (dc + ec)]
    out = []
    for b in range(nb):
        data = [cw[i * nb + b] for i in range(dc)]
        parity = [cw[dc * nb + i * nb + b] for i in range(ec)]
        word = data + parity
        for i in range(ec):
            s = 0
            for c in word:
                s = qr.gmul(s, qr._EXP[i]) ^ c
            assert s == 0, "Reed-Solomon syndrome non-zero"
        out += data
    bs = "".join(f"{c:08b}" for c in out)
    assert bs[:4] == "0100"
    n = int(bs[4:12], 2)
    return bytes(int(bs[12 + 8 * i:20 + 8 * i], 2) for i in range(n))


class QrTest(Quiet):
    def test_rs_known_answer(self):
        # ISO 18004 worked example ("HELLO WORLD", 1-M): data codewords -> parity
        data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
        self.assertEqual(qr.rs_remainder(data, 10), [196, 35, 39, 119, 235, 215, 231, 226, 93, 23])

    def test_format_info_known(self):
        # level M, mask 0 -> 101010000010010 (ISO 18004 format information table)
        self.assertEqual(qr.format_bits(0), 0b101010000010010)

    def test_wifi_payload_roundtrips(self):
        mat = qr.encode(QR)
        self.assertEqual(len(mat), 4 * 4 + 17)               # version 4 for 57 bytes
        self.assertEqual(decode(mat, 4), QR.encode())

    def test_finder_patterns_and_dark_module(self):
        mat = qr.encode("x")
        n = len(mat)
        for (cx, cy) in ((3, 3), (n - 4, 3), (3, n - 4)):
            self.assertTrue(mat[cy][cx])
            self.assertFalse(mat[cy][cx + 2])               # light ring
            self.assertTrue(mat[cy][cx + 3])                # dark border
        self.assertTrue(mat[n - 8][8])

    def test_all_versions(self):
        for ver, nbytes in ((1, 10), (2, 20), (3, 40), (4, 60), (5, 80), (6, 100)):
            p = bytes((i * 7 + 1) % 251 for i in range(nbytes))
            self.assertEqual(decode(qr.encode(p, ver), ver), p, ver)

    def test_too_long(self):
        with self.assertRaises(ValueError):
            qr.encode(b"x" * 107)

    def test_svg_path(self):
        d, side = qr.to_svg_path(qr.encode(QR))
        self.assertEqual(side, 33 + 8)
        self.assertTrue(d.startswith("M"))


if __name__ == "__main__":
    unittest.main()
