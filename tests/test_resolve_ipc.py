import importlib.util
import struct
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "ri", Path(__file__).parent / ".." / "tools" / "resolve_ipc.py")
ri = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ri)


class FlatImg:
    """Flat addressable image: put() then rva2off()/buf work on real RVAs."""

    def __init__(self, base=0x1000):
        self.base = base
        self.buf = bytearray(0x20000)

    def put(self, rva, data):
        self.buf[rva - self.base:rva - self.base + len(data)] = bytes(data)

    def rva2off(self, rva):
        return rva - self.base


RDATA, RSZ = 0x2000, 0x4000
SPANS = [(RDATA, RSZ)]
TD = b".?AVIClientUserMap@@"
TD_RVA = RDATA + 0x100
COL_RVA = RDATA + 0x200
VT_RVA = 0x5000
WRAP = VT_RVA + 0x1000  # value held in the vtable slot, not its address
BASE = 0x140000000


def mkimg(entries=(), with_td=True, with_col=True, col_sig=1,
          vt_slot_val=None, wrapper_hash=True):
    img = FlatImg()
    if with_td:
        img.put(TD_RVA, b"\x00" * 16 + TD + b"\x00")
    if with_col:
        img.put(COL_RVA, struct.pack("<IIIII", col_sig, 0, 0, TD_RVA, 0x9999))
        img.put(VT_RVA - 8, struct.pack("<Q", BASE + COL_RVA))
    slotval = WRAP if vt_slot_val is None else vt_slot_val
    img.put(VT_RVA + 10 * 8, struct.pack("<Q", BASE + slotval))
    if wrapper_hash:
        img.put(WRAP + 0x63, bytes.fromhex("D6FC3200")[::-1])
    ctx_entries = list(entries) or [WRAP]
    return img, ctx_entries


class TestLocateTd(unittest.TestCase):
    def test_found(self):
        img, _ = mkimg()
        self.assertEqual(ri.find_td(img, SPANS, TD), TD_RVA)

    def test_absent(self):
        img, _ = mkimg(with_td=False)
        self.assertIsNone(ri.find_td(img, SPANS, TD))


class TestLocateVtable(unittest.TestCase):
    def test_found(self):
        img, _ = mkimg()
        self.assertEqual(
            ri.find_vtable(img, SPANS, TD_RVA, BASE),
            (VT_RVA, None))

    def test_no_col_fails(self):
        img, _ = mkimg(with_col=False)
        v, e = ri.find_vtable(img, SPANS, TD_RVA, BASE)
        self.assertIsNone(v)
        self.assertIn("0 COL", e)

    def test_bad_sig_col_ignored(self):
        img, _ = mkimg(col_sig=0)
        v, e = ri.find_vtable(img, SPANS, TD_RVA, BASE)
        self.assertIsNone(v)
        self.assertIn("0 COL", e)

    def test_no_ref_fails(self):
        img, _ = mkimg()
        img.put(VT_RVA - 8, struct.pack("<Q", 0xDEAD))
        v, e = ri.find_vtable(img, SPANS, TD_RVA, BASE)
        self.assertIsNone(v)
        self.assertIn("0 vtable", e)

    def test_two_refs_fail(self):
        img, _ = mkimg()
        img.put(VT_RVA + 0x800 - 8, struct.pack("<Q", BASE + COL_RVA))
        v, e = ri.find_vtable(img, SPANS, TD_RVA, BASE)
        self.assertIsNone(v)
        self.assertIn("2 vtable", e)


class TestCheckWrapper(unittest.TestCase):
    def test_ok(self):
        img, entries = mkimg()
        self.assertTrue(ri.check_wrapper(img, WRAP, "D6FC3200", set(entries)))

    def test_not_in_pdata(self):
        img, _ = mkimg()
        self.assertFalse(ri.check_wrapper(img, WRAP, "D6FC3200", {0x1234}))

    def test_hash_missing(self):
        img, entries = mkimg(wrapper_hash=False)
        self.assertFalse(ri.check_wrapper(img, WRAP, "D6FC3200", set(entries)))


class TestExtractWireConstants(unittest.TestCase):
    @staticmethod
    def _append_u32(value):
        return (bytes.fromhex("41 B8 04 00 00 00 C7 44 24 20")
                + value.to_bytes(4, "little")
                + bytes.fromhex("48 8D 54 24 20 48 8D 4C 24 30"
                                " E8 00 00 00 00"))

    def test_extracts_only_immediates_serialized_as_u32(self):
        code = (bytes.fromhex("B8 11 22 33 44")
                + self._append_u32(0x09607EC2)
                + self._append_u32(0x0AFEF352))
        self.assertEqual(
            ri.extract_serialized_u32_constants(code, 0x1000),
            [0x09607EC2, 0x0AFEF352])

    def test_unserialized_immediates_are_ignored(self):
        code = bytes.fromhex("B8 11 22 33 44 48 83 C4 20 C3")
        self.assertEqual(ri.extract_serialized_u32_constants(code, 0x1000), [])

    def test_extracts_rbp_relative_stack_constants(self):
        def append_u32(value):
            return (bytes.fromhex("41 B8 04 00 00 00 C7 45 20")
                    + value.to_bytes(4, "little")
                    + bytes.fromhex("48 8D 55 20 48 8D 4D 30"
                                    " E8 00 00 00 00"))

        code = (bytes.fromhex("55 48 89 E5 48 83 EC 60")
                + append_u32(0xD6FC3200)
                + append_u32(0xD7058CA5))
        self.assertEqual(
            ri.extract_serialized_u32_constants(code, 0x1000),
            [0xD6FC3200, 0xD7058CA5])

    def test_extracts_immediate_materialized_in_register_then_spilled(self):
        def append_u32(value):
            return (bytes.fromhex("41 B8 04 00 00 00 B8")
                    + value.to_bytes(4, "little")
                    + bytes.fromhex("89 44 24 20 48 8D 54 24 20"
                                    " E8 00 00 00 00"))

        code = (bytes.fromhex("48 83 EC 60")
                + append_u32(0x09607EC0)
                + append_u32(0x0AFF7152))
        self.assertEqual(
            ri.extract_serialized_u32_constants(code, 0x1000),
            [0x09607EC0, 0x0AFF7152])

    def test_does_not_reuse_r8d_length_across_append_calls(self):
        code = (bytes.fromhex(
                    "48 83 EC 60 41 B8 04 00 00 00 "
                    "C7 44 24 20 11 22 33 44 "
                    "48 8D 54 24 20 E8 00 00 00 00 "
                    "C7 44 24 28 55 66 77 88 "
                    "48 8D 54 24 28 E8 00 00 00 00"))
        self.assertEqual(
            ri.extract_serialized_u32_constants(code, 0x1000),
            [0x44332211])


class TestResolveIface(unittest.TestCase):
    SPEC = {"id": 1, "td": TD,
            "methods": [("GetSteamID", 10, "D6FC3200", "D7058CA5", 0)]}

    def test_happy_path(self):
        img, entries = mkimg()
        vt, methods, err = ri.resolve_iface(
            self.SPEC, img, SPANS, BASE, set(entries))
        self.assertIsNone(err)
        self.assertEqual(vt, VT_RVA)
        self.assertEqual(methods, {"GetSteamID": WRAP})

    def test_bad_slot_fails(self):
        img, entries = mkimg()
        img.put(VT_RVA + 10 * 8, struct.pack("<Q", BASE + 0x9999))
        vt, methods, err = ri.resolve_iface(
            self.SPEC, img, SPANS, BASE, set(entries))
        self.assertIsNone(vt)
        self.assertIn("fails hash check", err)

    def test_getappid_wire_hash_is_derived_from_wrapper(self):
        img = FlatImg()
        img.put(TD_RVA, b"\x00" * 16 + ri.IPC_IFACES["IClientUtils"]["td"] + b"\x00")
        img.put(COL_RVA, struct.pack(
            "<IIIII", 1, 0, 0, TD_RVA, 0x9999))
        img.put(VT_RVA - 8, struct.pack("<Q", BASE + COL_RVA))
        img.put(VT_RVA + 19 * 8, struct.pack("<Q", BASE + WRAP))

        def append_u32(value):
            return (bytes.fromhex("41 B8 04 00 00 00 C7 44 24 20")
                    + value.to_bytes(4, "little")
                    + bytes.fromhex("48 8D 54 24 20 48 8D 4C 24 30"
                                    " E8 00 00 00 00"))

        code = (bytes.fromhex("55 48 89 E5 48 83 EC 60 B8 11 22 33 44")
                + append_u32(0x12345678)
                + append_u32(0xABCDEF01))
        img.put(WRAP, code)
        spec = ri.channel_spec(
            "IClientUtils", ri.IPC_IFACES["IClientUtils"], "beta")
        spec["methods"] = spec["methods"][:1]
        vt, methods, err = ri.resolve_iface(
            spec, img, SPANS, BASE, {WRAP}, {WRAP: len(code)})

        self.assertIsNone(err)
        self.assertEqual(vt, VT_RVA)
        self.assertEqual(methods, {"GetAppID": WRAP})
        self.assertEqual(spec["methods"][0],
                         ("GetAppID", 19, "12345678", "ABCDEF01", 0))

    def test_getsteamid_wire_pair_is_derived_from_rbp_wrapper(self):
        img, _ = mkimg()

        def append_u32(value):
            return (bytes.fromhex("41 B8 04 00 00 00 C7 45 20")
                    + value.to_bytes(4, "little")
                    + bytes.fromhex("48 8D 55 20 48 8D 4D 30"
                                    " E8 00 00 00 00"))

        code = (bytes.fromhex("55 48 89 E5 48 83 EC 60")
                + append_u32(0x11223344)
                + append_u32(0x55667788))
        img.put(WRAP, code)
        spec = {**self.SPEC, "methods": list(self.SPEC["methods"])}
        vt, methods, err = ri.resolve_iface(
            spec, img, SPANS, BASE, {WRAP}, {WRAP: len(code)})

        self.assertIsNone(err)
        self.assertEqual(vt, VT_RVA)
        self.assertEqual(methods, {"GetSteamID": WRAP})
        self.assertEqual(spec["methods"][0],
                         ("GetSteamID", 10, "11223344", "55667788", 0))


class TestRenderToml(unittest.TestCase):
    def test_schema_matches_upstream(self):
        spec = {"id": 1, "td": TD,
                "methods": [("GetSteamID", 10, "D6FC3200", "D7058CA5", 0)]}
        text = ri.render_toml([("IClientUser", spec, 0x1324AF0,
                                {"GetSteamID": 0x79F3C0})])
        self.assertEqual(text, """\
# MACHINE-GENERATED by tools/resolve_ipc.py - do not hand-edit
[IClientUser]
interface_id = 1
vtable_rva = "0x1324AF0"

[IClientUser.GetSteamID]
method_index = 10
funcHash = "0xD6FC3200"
wrapper_rva = "0x79F3C0"
fencepost = "0xD7058CA5"
argc = 0
""")


class TestChannelConstants(unittest.TestCase):
    def test_channels_cover_all_methods(self):
        for iface, spec in ri.IPC_IFACES.items():
            names = {m[0] for m in spec["methods"]}
            for channel in ri.IPC_CONSTANTS:
                self.assertEqual(set(ri.IPC_CONSTANTS[channel][iface]), names)

    def test_stable_and_beta_reroll_independently(self):
        stable = ri.channel_spec(
            "IClientUtils", ri.IPC_IFACES["IClientUtils"], "stable")
        beta = ri.channel_spec(
            "IClientUtils", ri.IPC_IFACES["IClientUtils"], "beta")
        self.assertEqual(stable["methods"][0],
                         ("GetAppID", 19, "09607EC4", "0AFE7552", 0))
        self.assertEqual(beta["methods"][0],
                         ("GetAppID", 19, "09607EC2", "0AFEF352", 0))


if __name__ == "__main__":
    unittest.main()
