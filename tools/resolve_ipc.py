"""Zero-seed IPC resolver: steamclient64.dll in, ipc/steamclient/<sha>.toml out.

Emits the IPC TOML schema the client parses in IPCLoader.cpp:
per-interface [Name] (interface_id, vtable_rva) plus per-method
[Name.Method] (method_index, funcHash, wrapper_rva, fencepost, argc).

funcHash / fencepost values are wire constants the wrapper writes into the
outgoing IPC buffer (4-byte appends). They are NOT build-stable. Every pair
is extracted from the wrapper selected through this build's vtable. Re-derive
on failure: inspect the slot's wrapper, find each
`mov dword ptr [..], imm32` followed by the 4-byte append helper call; first
immediate = funcHash, second = fencepost. Only the two RVAs resolve per
build. Resolution chain per interface, all asserted unique (FAIL loudly):

  RTTI TypeDescriptor name (pinned, e.g. .?AVIClientUserMap@@)
    -> Complete Object Locator (sig == 1, pTD == TD)
      -> vtable: the address X whose qword at X-8 == COL VA
        -> wrapper: qword at X + method_index * 8, must be a pdata entry
           whose first HASH_WINDOW bytes contain the method's funcHash.

Usage:
    python3 tools/resolve_ipc.py resolve --dll <dll> --channel stable
        --out-dir ipc/ [--verify <ground-truth.toml>]
"""

import argparse
import struct
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "rp", Path(__file__).parent / "resolve_patterns.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)

HASH_WINDOW = 0x400

# iface -> interface_id, RTTI TypeDescriptor name, and methods:
# (method, method_index, argc). Method order and indexes are wire-stable;
# only the funcHash/fencepost pair differs per channel.
IPC_IFACES = {
    "IClientUser": {
        "id": 1,
        "td": b".?AVIClientUserMap@@",
        "methods": [
            ("GetSteamID", 10, 0),
            ("GetAppOwnershipTicketExtendedData", 105, 2),
            ("RequestEncryptedAppTicket", 120, 2),
            ("GetEncryptedAppTicket", 121, 1),
        ],
    },
    "IClientUtils": {
        "id": 4,
        "td": b".?AVIClientUtilsMap@@",
        "methods": [
            ("GetAppID", 19, 0),
            ("GetAPICallResult", 24, 3),
        ],
    },
}

# Known wire-constant seeds: iface -> method -> (funcHash, fencepost).
# DLL resolution extracts the current values from the wrapper; these remain
# reference data for direct helper callers and regression tests.
IPC_CONSTANTS = {
    "stable": {
        "IClientUser": {
            "GetSteamID": ("D6FC3200", "D7058CA5"),
            "GetAppOwnershipTicketExtendedData": ("C7E71245", "C8449840"),
            "RequestEncryptedAppTicket": ("25D6BB1D", "2646B663"),
            "GetEncryptedAppTicket": ("E0468CB4", "E0B80200"),
        },
        "IClientUtils": {
            "GetAppID": ("09607EC4", "0AFE7552"),
            "GetAPICallResult": ("2D3D3947", "2EDF5EE6"),
        },
    },
    "beta": {
        "IClientUser": {
            "GetSteamID": ("D6FC3200", "D7058CA5"),
            "GetAppOwnershipTicketExtendedData": ("5578709F", "55D3418F"),
            "RequestEncryptedAppTicket": ("BBB80477", "BC2703B9"),
            "GetEncryptedAppTicket": ("25D6BB1C", "2646F563"),
        },
        "IClientUtils": {
            "GetAppID": ("09607EC2", "0AFEF352"),
            "GetAPICallResult": ("2D3D3979", "2EDFDD1A"),
        },
    },
}


def channel_spec(iface, spec, channel):
    """Attach the channel's wire constants to one interface spec."""
    consts = IPC_CONSTANTS[channel][iface]
    methods = []
    for name, idx, argc in spec["methods"]:
        func_hash, fence = consts[name]
        methods.append((name, idx, func_hash, fence, argc))
    return {**spec, "methods": methods}


def image_base(buf) -> int:
    e = struct.unpack_from("<I", buf, 0x3C)[0]
    return struct.unpack_from("<Q", buf, e + 48)[0]


def data_spans(img):
    """(rva, size) of data sections that can host RTTI (order-stable)."""
    return [(va, max(vsz, rawsz)) for name, va, vsz, _raw, rawsz in img.secs
            if name in (b".rdata", b".data")]


def span_bytes(img, rva, size):
    """Contiguous bytes for [rva, rva+size), crossing sections if needed."""
    out = bytearray()
    cur = rva
    while len(out) < size:
        o = img.rva2off(cur)
        if o is None:
            return None
        end = cur + 1
        while end < rva + size and img.rva2off(end) == o + (end - cur):
            end += 1
        out += bytes(img.buf[o:o + (end - cur)])
        cur = end
    return bytes(out)


def _u32(img, rva):
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<I", img.buf, o)[0]


def _u64(img, rva):
    o = img.rva2off(rva)
    if o is None:
        return None
    return struct.unpack_from("<Q", img.buf, o)[0]


def find_td(img, spans, name: bytes):
    """RVA of the TypeDescriptor whose mangled name matches (name at +16)."""
    cands = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        off = 0
        key = bytes(name) + b"\x00"
        while True:
            i = blob.find(key, off)
            if i < 0:
                break
            cands.add(rva + i - 16)
            off = i + 1
    if len(cands) != 1:
        return None
    return next(iter(cands))


def find_vtable(img, spans, td_rva, base):
    """The one address X whose qword at X-8 is the VA of a COL for td."""
    cols = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 4, 4):
            if struct.unpack_from("<I", blob, i)[0] != td_rva:
                continue
            col = rva + i - 12
            if _u32(img, col) == 1:
                cols.add(col)
    if not cols:
        return None, "0 COL cands"
    want = {base + c for c in cols}
    match = set()
    for rva, size in spans:
        blob = span_bytes(img, rva, size)
        if blob is None:
            continue
        for i in range(0, len(blob) - 8, 8):
            if struct.unpack_from("<Q", blob, i)[0] in want:
                match.add(rva + i + 8)
    if len(match) != 1:
        return None, f"{len(match)} vtable cands"
    return next(iter(match)), None


def check_wrapper(img, func_rva, funchash: str, pdata,
                  pdata_sizes=None) -> bool:
    if func_rva not in pdata:
        return False
    o = img.rva2off(func_rva)
    if o is None:
        return False
    window = HASH_WINDOW
    if pdata_sizes is not None:
        size = pdata_sizes.get(func_rva, 0)
        if size <= 0:
            return False
        window = min(window, size)
    return bytes.fromhex(funchash)[::-1] in bytes(img.buf[o:o + window])


def extract_serialized_u32_constants(code: bytes, base_rva: int) -> list[int]:
    """Extract stack u32 literals serialized through a 4-byte IPC append.

    IPC wrappers place each wire constant in a stack temporary, pass that
    temporary as RDX with R8D=4, then call the common append helper. Requiring
    that instruction shape avoids treating unrelated immediates as hashes.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_INS_CALL, X86_INS_LEA, X86_INS_MOV,
        X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
        X86_REG_R8D, X86_REG_RBP, X86_REG_RDX, X86_REG_RSP,
    )

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, base_rva))
    values = []
    for index, ins in enumerate(instructions):
        if ins.id != X86_INS_MOV or len(ins.operands) != 2:
            continue
        dst, src = ins.operands
        if (dst.type != X86_OP_MEM or dst.size != 4
                or dst.mem.base not in (X86_REG_RSP, X86_REG_RBP)
                or dst.mem.index != 0
                or src.type != X86_OP_IMM):
            continue

        window_start = max(0, index - 2)
        window_end = min(len(instructions), index + 7)
        window = instructions[window_start:window_end]
        append_ptr = False
        append_size = False
        append_call = False
        for candidate in window:
            if candidate.address <= ins.address:
                if (candidate.id == X86_INS_MOV and len(candidate.operands) == 2
                        and candidate.operands[0].type == X86_OP_REG
                        and candidate.operands[0].reg == X86_REG_R8D
                        and candidate.operands[1].type == X86_OP_IMM
                        and candidate.operands[1].imm == 4):
                    append_size = True
                continue
            if candidate.id == X86_INS_LEA and len(candidate.operands) == 2:
                dst_reg, src_mem = candidate.operands
                if (dst_reg.type == X86_OP_REG and dst_reg.reg == X86_REG_RDX
                        and src_mem.type == X86_OP_MEM
                        and src_mem.mem.base == dst.mem.base
                        and src_mem.mem.index == 0
                        and src_mem.mem.disp == dst.mem.disp):
                    append_ptr = True
            elif candidate.id == X86_INS_CALL and append_ptr:
                append_call = True
                break
        if append_ptr and append_size and append_call:
            values.append(src.imm & 0xFFFFFFFF)
    return values


def serialized_u32_constants(img, func_rva, pdata_sizes):
    size = pdata_sizes.get(func_rva, 0)
    off = img.rva2off(func_rva)
    if size <= 0 or off is None:
        return []
    end = min(off + size, len(img.buf))
    return extract_serialized_u32_constants(
        bytes(img.buf[off:end]), func_rva)


def resolve_iface(spec, img, spans, base, pdata, pdata_sizes=None):
    td = find_td(img, spans, spec["td"])
    if td is None:
        return None, None, f'no TD {spec["td"]!r}'
    vt, err = find_vtable(img, spans, td, base)
    if err is not None:
        return None, None, err
    methods = {}
    for method_index, (name, idx, funchash, fence, argc) in enumerate(
            list(spec["methods"])):
        f = _u64(img, vt + idx * 8)
        if f is None:
            return None, None, f"slot {idx} unreadable"
        f -= base

        # IPC wire constants can roll independently on stable/beta. Derive
        # them from the vtable-selected wrapper rather than accepting stale
        # channel constants when this build changes. Dynamic method arguments
        # are loaded from registers, so only the two serialized immediates
        # (funcHash, fencepost) are returned by the extractor.
        if pdata_sizes is not None:
            wire = serialized_u32_constants(img, f, pdata_sizes)
            if len(wire) != 2:
                return None, None, (
                    f"{name}: couldn't extract funcHash/fencepost from "
                    f"wrapper {f:#x} (found {len(wire)} serialized u32 values)")
            funchash, fence = (f"{wire[0]:08X}", f"{wire[1]:08X}")
            methods_spec = list(spec["methods"])
            methods_spec[method_index] = (name, idx, funchash, fence, argc)
            spec["methods"] = methods_spec
            spec.setdefault("wire_constants_updated", []).append(name)
        if not check_wrapper(img, f, funchash, pdata, pdata_sizes):
            return None, None, f"{name}: wrapper {f:#x} fails hash check"
        methods[name] = f
    return vt, methods, None


def render_toml(resolved) -> str:
    parts = []
    for iface, spec, vt, methods in resolved:
        parts.append("\n".join(
            [f"[{iface}]", f'interface_id = {spec["id"]}',
             f'vtable_rva = "0x{vt:X}"']))
        for name, idx, funchash, fence, argc in spec["methods"]:
            parts.append("\n".join(
                [f"[{iface}.{name}]", f"method_index = {idx}",
                 f'funcHash = "0x{funchash.upper()}"',
                 f'wrapper_rva = "0x{methods[name]:X}"',
                 f'fencepost = "0x{fence.upper()}"', f"argc = {argc}"]))
    head = "# MACHINE-GENERATED by tools/resolve_ipc.py - do not hand-edit"
    return head + "\n" + "\n\n".join(parts) + "\n"


def cmd_resolve(args):
    dll = Path(args.dll)
    img = rp.mp.Image(dll)
    spans = data_spans(img)
    if not spans:
        print("FAIL: no data sections")
        return 1
    base = image_base(img.buf)
    pdata_ranges = img.pdata_ranges()
    entries = sorted(begin for begin, _end in pdata_ranges)
    pdata = set(entries)
    pdata_sizes = {begin: end - begin for begin, end in pdata_ranges}
    resolved, failed = [], []
    for iface, base_spec in IPC_IFACES.items():
        spec = channel_spec(iface, base_spec, args.channel)
        vt, methods, err = resolve_iface(
            spec, img, spans, base, pdata, pdata_sizes)
        if err is not None:
            failed.append((iface, err))
            print(f"FAIL {iface}: {err}")
        else:
            resolved.append((iface, spec, vt, methods))
            print(f"{iface}: vtable=0x{vt:X} " +
                  " ".join(f"{m}=0x{w:X}" for m, w in methods.items()))
            for method in spec.get("wire_constants_updated", ()):
                values = next(m for m in spec["methods"] if m[0] == method)
                print(f"AUTO {iface}.{method}: funcHash=0x{values[2]} "
                      f"fencepost=0x{values[3]}")
    if args.verify:
        truth = tomllib.load(open(args.verify, "rb"))
        for iface, spec, vt, methods in resolved:
            t = truth.get(iface, {})
            mark = "OK" if t.get("vtable_rva") == f"0x{vt:X}" else \
                f'MISMATCH truth={t.get("vtable_rva")}'
            print(f"{mark} {iface}.vtable_rva")
            for name, idx, funchash, _fence, _argc in spec["methods"]:
                tm = truth.get(iface, {}).get(name, {})
                mark = "OK" if tm.get("wrapper_rva") == \
                    f'0x{methods[name]:X}' else \
                    f'MISMATCH truth={tm.get("wrapper_rva")}'
                print(f"{mark} {iface}.{name}.wrapper_rva")
    if args.out_dir and not failed:
        from hashlib import sha256
        text = render_toml(resolved)
        out = Path(args.out_dir) / "steamclient" / f"{sha256(dll.read_bytes()).hexdigest()}.toml"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, newline="\n")
        print(f"wrote {out}")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--dll", required=True)
    r.add_argument("--channel", required=True, choices=sorted(IPC_CONSTANTS))
    r.add_argument("--out-dir", default=None)
    r.add_argument("--verify", default=None)
    args = ap.parse_args()
    if args.cmd == "resolve":
        return cmd_resolve(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
