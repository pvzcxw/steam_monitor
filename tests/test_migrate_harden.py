import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "mp", Path(__file__).parent / ".." / "tools" / "migrate_patterns.py")
mp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mp)


class TestHardenSig(unittest.TestCase):
    def test_extends_to_unique(self):
        seen = []

        def scan(toks):
            seen.append(len(toks))
            return [0x100, 0x200] if len(toks) < 4 else [0x100]

        out = mp.harden_sig(["AA", "BB"], 0x100,
                            bytes.fromhex("AA BB CC DD EE"), scan)
        self.assertEqual(out, "AA BB CC DD")
        self.assertEqual(seen, [3, 4])

    def test_unique_hit_must_be_true_rva(self):
        out = mp.harden_sig(["AA", "BB"], 0x100,
                            bytes.fromhex("AA BB CC DD"),
                            lambda toks: [0x200])
        self.assertIsNone(out)


class TestPdataRecords(unittest.TestCase):
    def _write_image(self, path):
        """Build a tiny PE32+ image with root, chained, and invalid entries."""
        buf = bytearray(0x3400)
        pe = 0x80
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, pe)
        buf[pe:pe + 4] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", buf, pe + 4,
                         0x8664, 3, 0, 0, 0, 0xF0, 0x2022)
        opt = pe + 24
        struct.pack_into("<H", buf, opt, 0x20B)
        struct.pack_into("<II", buf, opt + 112 + 8 * 3, 0x3000, 36)

        sec = opt + 0xF0
        sections = [
            (b".text", 0x1000, 0x1000, 0x400, 0x1000),
            (b".pdata", 0x3000, 0x1000, 0x1400, 0x1000),
            (b".xdata", 0x4000, 0x1000, 0x2400, 0x1000),
        ]
        for i, (name, va, vsz, raw, rawsz) in enumerate(sections):
            struct.pack_into("<8sIIIIIIHHI", buf, sec + i * 40,
                             name, vsz, va, rawsz, raw, 0, 0, 0, 0,
                             0x60000020)

        records = [
            (0x1000, 0x1080, 0x4000),
            (0x1100, 0x1120, 0x4010),
            (0x1200, 0x1220, 0x4030),
        ]
        pdata_off = 0x1400
        for i, record in enumerate(records):
            struct.pack_into("<III", buf, pdata_off + i * 12, *record)

        # The child has one unwind-code slot: CHAININFO must align it to two
        # slots, so its parent RUNTIME_FUNCTION starts at +8, not +6.
        buf[0x2400:0x2408] = b"\x01\x00\x00\x00\x00\x00\x00\x00"
        buf[0x2410:0x2418] = b"\x21\x00\x01\x00\x01\x00\x00\x00"
        struct.pack_into("<III", buf, 0x2418, *records[0])
        buf[0x2430:0x2434] = b"\x21\x00\x00\x00"
        # Same parent begin but mismatched end: reject as an invalid chain.
        struct.pack_into("<III", buf, 0x2434,
                         records[0][0], records[0][1] + 1, records[0][2])
        path.write_bytes(buf)

    def test_chaininfo_odd_unwind_slot_and_bad_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.dll"
            self._write_image(path)
            img = mp.Image(path)

        self.assertEqual(img.pdata_records(), [
            (0x1000, 0x1080, None),
            (0x1100, 0x1120, 0x1000),
            (0x1200, 0x1220, mp.INVALID_PDATA_CHAIN),
        ])

    def test_none_when_cap_reached(self):
        out = mp.harden_sig(["AA"], 0x100, bytes.fromhex("AA BB"),
                            lambda toks: [0x100, 0x200])
        self.assertIsNone(out)

    def test_none_when_no_bytes_left(self):
        out = mp.harden_sig(["AA", "BB"], 0x100, bytes.fromhex("AA BB"),
                            lambda toks: [0x100, 0x200])
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main()
