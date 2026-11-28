"""Zero-seed IPC resolver: steamclient64.dll in, ipc/steamclient/<sha>.toml out.

Emits the IPC TOML schema the client parses in IPCLoader.cpp:
per-interface [Name] (interface_id, vtable_rva) plus per-method
[Name.Method] (method_index, funcHash, wrapper_rva, fencepost, argc).

funcHash / fencepost values are wire constants the wrapper writes into the
outgoing IPC buffer (4-byte appends). They are NOT build-stable. Pairs are
extracted from the wrapper selected through this build's vtable; GetSteamID
has a narrow, wrapper-hash-validated channel-seed fallback for unrecognized
codegen. Re-derive on failure: inspect the slot's wrapper, find each
`mov dword ptr [..], imm32` followed by the 4-byte append helper call; first
immediate = funcHash, second = fencepost. Wrapper RVAs and wire pairs are
resolved per build. Resolution chain per interface, all asserted unique (FAIL
loudly):

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
            "GetAppID": ("09607EC0", "0AFF7152"),
            "GetAPICallResult": ("2D3D397B", "2EE05B1E"),
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


def pdata_families(img):
    """Group chained x64 exception records by their primary function."""
    records = {
        begin: (end, parent)
        for begin, end, parent in img.pdata_records()
    }
    roots = {}

    def root(begin):
        if begin in roots:
            return roots[begin]
        path = []
        seen = set()
        current = begin
        while current in records and current not in seen:
            if current in roots:
                resolved = roots[current]
                break
            seen.add(current)
            path.append(current)
            parent = records[current][1]
            if parent is None:
                resolved = current
                break
            if parent not in records:
                resolved = None
                break
            current = parent
        else:
            resolved = None
        for item in path:
            roots[item] = resolved
        return resolved

    families = {}
    for begin in records:
        primary = root(begin)
        if primary is not None:
            families.setdefault(primary, []).append(begin)
    for family in families.values():
        family.sort()
    return families


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


def _family_for(func_rva, pdata_families):
    if pdata_families is None:
        return [func_rva]
    for family in pdata_families.values():
        if func_rva in family:
            return family
    return [func_rva]


def check_wrapper(img, func_rva, funchash: str, pdata,
                  pdata_sizes=None, pdata_families=None) -> bool:
    if func_rva not in pdata:
        return False
    needle = bytes.fromhex(funchash)[::-1]
    for fragment in _family_for(func_rva, pdata_families):
        o = img.rva2off(fragment)
        if o is None:
            continue
        window = HASH_WINDOW
        if pdata_sizes is not None:
            size = pdata_sizes.get(fragment, 0)
            if size <= 0:
                continue
            window = min(window, size)
        if needle in bytes(img.buf[o:o + window]):
            return True
    return False


def extract_serialized_u32_constants(code: bytes, base_rva: int) -> list[int]:
    """Extract stack u32 literals serialized through a 4-byte IPC append.

    IPC wrappers place each wire constant in a stack temporary, pass that
    temporary as RDX with R8D=4, then call the common append helper. Requiring
    that instruction shape avoids treating unrelated immediates as hashes.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86_const import (
        X86_INS_ADD, X86_INS_CALL, X86_INS_LEA, X86_INS_MOV,
        X86_INS_POP, X86_INS_PUSH, X86_INS_SUB,
        X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
        X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_R8, X86_REG_R8D,
        X86_REG_R9, X86_REG_R9D, X86_REG_R10, X86_REG_R10D,
        X86_REG_R11, X86_REG_R11D, X86_REG_RAX, X86_REG_RBP,
        X86_REG_RCX, X86_REG_RDX, X86_REG_RSP,
    )

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, base_rva))
    # Track stack-relative aliases and immediate values in registers. Some
    # compiler versions write an immediate directly to a stack temporary;
    # others materialize it in a register first. Both are serialized through
    # the same append call with RDX pointing at the temporary and R8D == 4.
    aliases = {X86_REG_RSP: 0}
    constants = {}
    r8_value = None
    stack_stores = []
    before = []

    def stack_offset(mem):
        if mem.index != 0 or mem.base not in aliases:
            return None
        return aliases[mem.base] + mem.disp

    def address_key(mem):
        """Register-relative address identity, even without a known stack root."""
        if mem.base == 0 or mem.index != 0:
            return None
        return mem.base, mem.index, mem.scale, mem.disp

    for index, ins in enumerate(instructions):
        before.append((dict(aliases), r8_value))
        ops = ins.operands

        # Capture a 32-bit literal written to a stack-local slot.
        if ins.id == X86_INS_MOV and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_MEM and dst.size in (4, 8):
                offset = stack_offset(dst.mem)
                key = address_key(dst.mem)
                value = None
                if src.type == X86_OP_IMM:
                    value = src.imm
                elif src.type == X86_OP_REG and src.reg in constants:
                    value = constants[src.reg]
                if key is not None and value is not None:
                    stack_stores.append((index, offset, key,
                                         value & 0xFFFFFFFF))

        # Maintain aliases/constants for the common x64 compiler forms.
        if ins.id == X86_INS_PUSH:
            if X86_REG_RSP in aliases:
                aliases[X86_REG_RSP] -= 8
        elif ins.id == X86_INS_POP:
            if ops and ops[0].type == X86_OP_REG:
                aliases.pop(ops[0].reg, None)
                constants.pop(ops[0].reg, None)
            if X86_REG_RSP in aliases:
                aliases[X86_REG_RSP] += 8
        elif ins.id in (X86_INS_ADD, X86_INS_SUB) and len(ops) == 2 \
                and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_RSP \
                and ops[1].type == X86_OP_IMM and X86_REG_RSP in aliases:
            delta = ops[1].imm * (1 if ins.id == X86_INS_ADD else -1)
            aliases[X86_REG_RSP] += delta

        if ops and ops[0].type == X86_OP_REG:
            dst_reg = ops[0].reg
            adjusts_rsp = dst_reg == X86_REG_RSP and ins.id in (
                X86_INS_ADD, X86_INS_SUB)
            if not adjusts_rsp:
                aliases.pop(dst_reg, None)
                constants.pop(dst_reg, None)
            if dst_reg in (X86_REG_R8, X86_REG_R8D):
                r8_value = None
            if ins.id == X86_INS_MOV and len(ops) == 2:
                src = ops[1]
                if src.type == X86_OP_IMM:
                    constants[dst_reg] = src.imm & 0xFFFFFFFF
                elif src.type == X86_OP_REG:
                    if src.reg in aliases:
                        aliases[dst_reg] = aliases[src.reg]
                    if src.reg in constants:
                        constants[dst_reg] = constants[src.reg]
                elif src.type == X86_OP_MEM:
                    offset = stack_offset(src.mem)
                    if offset is not None:
                        aliases[dst_reg] = offset
            elif ins.id == X86_INS_LEA and len(ops) == 2 \
                    and ops[1].type == X86_OP_MEM:
                offset = stack_offset(ops[1].mem)
                if offset is not None:
                    aliases[dst_reg] = offset
            if dst_reg == X86_REG_R8D and ins.id == X86_INS_MOV \
                    and len(ops) == 2 and ops[1].type == X86_OP_IMM:
                r8_value = ops[1].imm & 0xFFFFFFFF

        # Calls clobber Windows x64 volatile registers. Preserve the snapshot
        # above for matching the current append call, then discard aliases and
        # literals that cannot be trusted after it returns.
        if ins.id == X86_INS_CALL:
            for reg in (X86_REG_RAX, X86_REG_EAX, X86_REG_RCX,
                        X86_REG_ECX, X86_REG_RDX, X86_REG_EDX,
                        X86_REG_R8, X86_REG_R8D, X86_REG_R9, X86_REG_R9D,
                        X86_REG_R10, X86_REG_R10D, X86_REG_R11, X86_REG_R11D):
                aliases.pop(reg, None)
                constants.pop(reg, None)
            r8_value = None

    values = []
    for store_index, slot, store_address, value in stack_stores:
        aliases_at_store, _ = before[store_index]
        append_ptr = (slot is not None
                      and aliases_at_store.get(X86_REG_RDX) == slot)
        for index in range(store_index + 1,
                           min(len(instructions), store_index + 9)):
            ins = instructions[index]
            aliases_before, r8_before = before[index]
            ops = ins.operands

            # A serialized u32 must be passed by its stack address in RDX.
            writes_rdx = bool(ops and ops[0].type == X86_OP_REG
                              and ops[0].reg in (X86_REG_RDX, X86_REG_EDX))
            if writes_rdx:
                append_ptr = (slot is not None
                              and aliases_before.get(X86_REG_RDX) == slot)
                if ins.id == X86_INS_LEA and len(ops) == 2 \
                        and ops[1].type == X86_OP_MEM:
                    offset = aliases_before.get(ops[1].mem.base)
                    same_address = address_key(ops[1].mem) == store_address
                    if same_address or (offset is not None
                                        and ops[1].mem.index == 0
                                        and slot is not None
                                        and offset + ops[1].mem.disp == slot):
                        append_ptr = True
                elif ins.id == X86_INS_MOV and len(ops) == 2 \
                        and ops[1].type == X86_OP_REG:
                    append_ptr = aliases_before.get(ops[1].reg) == slot

            if ins.id == X86_INS_CALL:
                if append_ptr and r8_before == 4:
                    values.append(value)
                break

    return values


def serialized_u32_constants(img, func_rva, pdata_sizes, pdata_families=None):
    values = []
    for fragment in _family_for(func_rva, pdata_families):
        size = pdata_sizes.get(fragment, 0)
        off = img.rva2off(fragment)
        if size <= 0 or off is None:
            continue
        end = min(off + size, len(img.buf))
        values.extend(extract_serialized_u32_constants(
            bytes(img.buf[off:end]), fragment))
    return values


def describe_wrapper(img, func_rva, pdata_sizes, pdata_families=None,
                     max_instructions=96):
    """Compact disassembly for failed IPC resolution triage logs."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    lines = []
    count = 0
    for fragment in _family_for(func_rva, pdata_families):
        size = pdata_sizes.get(fragment, 0)
        off = img.rva2off(fragment)
        if size <= 0 or off is None:
            lines.append(f"wrapper fragment unavailable: rva={fragment:#x}")
            continue
        code = bytes(img.buf[off:min(off + size, len(img.buf))])
        lines.append(f"wrapper extent: rva={fragment:#x} size={len(code):#x}")
        for ins in md.disasm(code, fragment):
            if count >= max_instructions:
                lines.append("... disassembly truncated ...")
                return "\n".join(lines)
            raw = ins.bytes.hex(" ")
            lines.append(f"{ins.address:08X}: {raw:<32} {ins.mnemonic} {ins.op_str}".rstrip())
            count += 1
    return "\n".join(lines)


def resolve_iface(spec, img, spans, base, pdata, pdata_sizes=None,
                  pdata_families=None):
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
            wire = serialized_u32_constants(
                img, f, pdata_sizes, pdata_families)
            if len(wire) == 2:
                funchash, fence = (f"{wire[0]:08X}", f"{wire[1]:08X}")
                methods_spec = list(spec["methods"])
                methods_spec[method_index] = (name, idx, funchash, fence, argc)
                spec["methods"] = methods_spec
                spec.setdefault("wire_constants_updated", []).append(name)
            elif name == "GetSteamID" and check_wrapper(
                    img, f, funchash, pdata, pdata_sizes, pdata_families):
                # Known Steam builds keep the GetSteamID wire pair stable,
                # but some wrapper codegen variants don't expose its stack
                # literal stores to the generic extractor. Use this narrow
                # channel seed fallback only when the selected wrapper itself
                # contains the seeded funcHash; otherwise fail closed.
                spec.setdefault("wire_constants_fallback", []).append(name)
            else:
                details = describe_wrapper(
                    img, f, pdata_sizes, pdata_families)
                return None, None, (
                    f"{name}: couldn't extract funcHash/fencepost from "
                    f"wrapper {f:#x} (found {len(wire)} serialized u32 values)\n"
                    f"{details}")
        if not check_wrapper(
                img, f, funchash, pdata, pdata_sizes, pdata_families):
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
    families = pdata_families(img)
    resolved, failed = [], []
    for iface, base_spec in IPC_IFACES.items():
        spec = channel_spec(iface, base_spec, args.channel)
        vt, methods, err = resolve_iface(
            spec, img, spans, base, pdata, pdata_sizes, families)
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
            for method in spec.get("wire_constants_fallback", ()):
                values = next(m for m in spec["methods"] if m[0] == method)
                print(f"SEED {iface}.{method}: funcHash=0x{values[2]} "
                      f"fencepost=0x{values[3]} (wrapper hash verified)")
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
