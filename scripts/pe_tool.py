#!/usr/bin/env python3
"""pe_tool.py - read-only PE inspector for offset work.

Stdlib only. ``disasm`` additionally needs capstone (optional).

Subcommands
-----------
  sections <pe>                       section table (name, VA, vsize, raw, flags)
  verify   <pe> <spec>                L0/L1/L2 verdict for each "name=rva" line
  thunk    <pe> <rva> [--depth N]     follow E9 rel32 chains, print the real target
  disasm   <pe> <rva> [--len N]       disassemble around an RVA
  slotmap  <pe> <start> <end> [--src DIR] [--step 8]
                                      qword slots holding code RVAs, cross-referenced
                                      against decompiled sources

``<spec>`` is a text file (or '-' for stdin) with one entry per line:
      name=rva            # 0x prefix optional
      name=0x1234ABCD     # comments after # are ignored

Exit code is 0 even when entries fail verification; read the verdict column.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path

# ----------------------------------------------------------------------------- PE
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000


class PE:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        if d[:2] != b"MZ":
            raise SystemExit(f"{self.path}: not a PE (no MZ)")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise SystemExit(f"{self.path}: not a PE (no PE signature)")
        opt = e_lfanew + 24
        magic = struct.unpack_from("<H", d, opt)[0]
        self.is64 = magic == 0x20B
        self.image_base = struct.unpack_from("<Q" if self.is64 else "<I", d, opt + 24)[0]
        nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", d, e_lfanew + 20)[0]
        sec_off = opt + opt_size

        self.sections: list[dict] = []
        for i in range(nsec):
            o = sec_off + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("latin1", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
            chars = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append({
                "name": name,
                "va": vaddr,
                "vsize": vsize,
                "raw_ptr": rawptr,
                "raw_size": rawsize,
                "flags": chars,
                "code": bool(chars & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)),
            })

    # -- address translation ---------------------------------------------------
    def section_of(self, rva: int) -> dict | None:
        for s in self.sections:
            span = max(s["vsize"], s["raw_size"])
            if s["va"] <= rva < s["va"] + span:
                return s
        return None

    def offset_of(self, rva: int) -> int | None:
        s = self.section_of(rva)
        if not s:
            return None
        delta = rva - s["va"]
        if delta >= s["raw_size"]:
            return None        # inside .bss-like tail, no file bytes
        return s["raw_ptr"] + delta

    def read(self, rva: int, n: int) -> bytes:
        off = self.offset_of(rva)
        if off is None:
            return b""
        return self.data[off:off + n]

    def read_ptr(self, rva: int) -> int | None:
        raw = self.read(rva, 8 if self.is64 else 4)
        if len(raw) != (8 if self.is64 else 4):
            return None
        return struct.unpack("<Q" if self.is64 else "<I", raw)[0]

    def code_sections(self) -> list[dict]:
        return [s for s in self.sections if s["code"]]

    def in_code(self, rva: int) -> bool:
        s = self.section_of(rva)
        return bool(s and s["code"])

    # -- function starts -------------------------------------------------------
    def function_starts(self) -> set[int] | None:
        """Real function entries from the exception directory (.pdata on x64).

        Never infer function starts by scanning backwards for padding: on optimised
        targets that returns mid-function addresses. .pdata is the trustworthy source
        when there are no symbols -- but only when it is actually readable.

        Protected builds sometimes encrypt or virtualise the exception directory; the
        raw bytes then look random and every "start" lands outside the code sections.
        Detect that and return None so callers can downgrade the evidence instead of
        reporting a false failure.
        """
        blob_all = b""
        for s in self.sections:
            if s["name"] in (".pdata", "pdata"):
                blob_all += self.data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]]
        if len(blob_all) < 12:
            return None

        entries = len(blob_all) // 12
        sample_step = max(1, entries // 2000)
        valid = 0
        sampled = 0
        for e in range(0, entries, sample_step):
            begin = struct.unpack_from("<I", blob_all, e * 12)[0]
            sampled += 1
            if begin >= 0x1000 and self.in_code(begin):
                valid += 1
        if sampled == 0 or valid * 100 // sampled < 90:
            return None                      # encrypted / not a real directory

        starts: set[int] = set()
        for e in range(entries):
            begin = struct.unpack_from("<I", blob_all, e * 12)[0]
            if begin:
                starts.add(begin)
        return starts if starts else None


# ----------------------------------------------------------------------- thunks
def follow_thunk(pe: PE, rva: int, depth: int = 4) -> tuple[int, list[int]]:
    """Follow ``E9 rel32`` jump stubs. Returns (final_rva, chain)."""
    chain = [rva]
    cur = rva
    for _ in range(depth):
        head = pe.read(cur, 5)
        if len(head) < 5 or head[0] != 0xE9:
            return cur, chain
        rel = struct.unpack_from("<i", head, 1)[0]
        nxt = cur + 5 + rel
        if not pe.in_code(nxt) or nxt in chain:
            return cur, chain     # bad displacement or loop: stop where we are
        chain.append(nxt)
        cur = nxt
    return cur, chain


def looks_like_entry(pe: "PE", rva: int) -> tuple[int, str]:
    """Judge whether `rva` looks like a function entry, without a symbol table.

    Returns (score, reason) where score is 0..2. The two independent signals are a
    plausible prologue and a plausible boundary (the bytes before it end in padding or a
    return). Two signals is soft-L1; one signal is weak; zero is "mid-function".

    This is deliberately *soft* evidence. When the exception directory is readable, trust
    it instead -- see PE.function_starts().
    """
    body = pe.read(rva, 8)
    if len(body) < 4:
        return 0, "unreadable"

    b0 = body[0]
    prologue = False

    # plain one-byte pushes used as a frame save
    if b0 in (0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
        prologue = True
    # REX-prefixed forms: push, sub rsp, and rsp, mov [rsp+x], reg, mov reg, rsp, lea
    elif b0 in (0x40, 0x41, 0x48, 0x49, 0x4C, 0x4D) and len(body) >= 3:
        b1, b2 = body[1], body[2]
        if 0x50 <= b1 <= 0x57:                       # push r8..r15 / rax..rdi
            prologue = True
        elif b1 == 0x83 and b2 in (0xEC, 0xE4):      # sub rsp, imm8 / and rsp, imm8
            prologue = True
        elif b1 == 0x81 and b2 == 0xEC:              # sub rsp, imm32
            prologue = True
        elif b1 == 0x89:                             # mov [rsp+x], reg (saves args)
            prologue = True
        elif b1 == 0x8D:                             # lea rsp, [rsp-x]
            prologue = True
        elif b1 == 0x8B and b2 in (0xC4, 0xFF):      # mov rax,rsp / mov rdi,rdi
            prologue = True

    # boundary: padding or a return immediately before the candidate
    boundary = False
    prev = pe.read(rva - 4, 4) if rva >= 4 else b""
    if len(prev) == 4:
        if prev == b"\xCC\xCC\xCC\xCC" or prev == b"\x90\x90\x90\x90":
            boundary = True
        elif prev[3] in (0xC3, 0xCC) or (prev[2] == 0xC3 and prev[3] == 0xCC):
            boundary = True

    if not prologue and not boundary:
        return 0, "no prologue and no boundary (mid-function)"
    if prologue and boundary:
        return 2, "prologue + boundary"
    return 1, ("prologue only" if prologue else "boundary only")


def hexbytes(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


# ---------------------------------------------------------------------- commands
def cmd_sections(pe: PE, _args) -> None:
    print(f"{pe.path.name}  image_base=0x{pe.image_base:X}  {len(pe.sections)} sections")
    print(f"{'name':10} {'VA':>12} {'vsize':>12} {'raw':>12} {'rawsize':>12}  code")
    for s in pe.sections:
        print(f"{s['name']:10} 0x{s['va']:010X} 0x{s['vsize']:010X} "
              f"0x{s['raw_ptr']:010X} 0x{s['raw_size']:010X}  {'yes' if s['code'] else ''}")


def load_spec(spec: str) -> list[tuple[str, int]]:
    text = sys.stdin.read() if spec == "-" else Path(spec).read_text(encoding="utf-8-sig")
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            name, val = line.split("=", 1)
        else:
            name, val = "", line
        val = val.strip()
        try:
            out.append((name.strip() or "?", int(val, 0)))
        except ValueError:
            print(f"! skip unparsable line: {line}", file=sys.stderr)
    return out


def cmd_verify(pe: PE, args) -> None:
    starts = pe.function_starts()
    if starts is None:
        print("# note: .pdata is unreadable on this build (encrypted or absent); "
              "L1 falls back to a prologue test and is reported as SOFT", file=sys.stderr)

    rows = []
    for name, rva in load_spec(args.spec):
        sect = pe.section_of(rva)
        sec_name = sect["name"] if sect else "-"
        in_code = pe.in_code(rva)
        final, chain = follow_thunk(pe, rva) if in_code else (rva, [rva])
        body = pe.read(final, 8)
        is_start = bool(starts) and rva in starts
        soft_score, soft_reason = looks_like_entry(pe, rva)

        if not in_code:
            verdict = "L0-FAIL not in code section"
        elif starts is not None:
            # strict mode: the exception directory is trustworthy here
            if not is_start:
                verdict = "L1-FAIL not a function entry"
            elif len(chain) > 1:
                verdict = f"L2-THUNK use 0x{final:X}"
            elif soft_score == 0:
                verdict = "L2-WARN odd prologue"
            else:
                verdict = "L0/L1/L2 OK"
        else:
            # soft mode: no reliable entry table
            if len(chain) > 1:
                verdict = f"L2-THUNK use 0x{final:X}"
            elif soft_score == 2:
                verdict = "L0/L1 SOFT-OK " + soft_reason
            elif soft_score == 1:
                verdict = "L1-WEAK " + soft_reason
            else:
                verdict = "L1-FAIL " + soft_reason

        rows.append({
            "name": name, "rva": f"0x{rva:X}", "section": sec_name,
            "pdata": is_start if starts is not None else None,
            "pdata_available": starts is not None,
            "final": f"0x{final:X}",
            "chain": [f"0x{c:X}" for c in chain], "bytes": hexbytes(body),
            "soft_l1": soft_score, "soft_l1_reason": soft_reason,
            "verdict": verdict,
        })

    width = max((len(r["name"]) for r in rows), default=4)
    for r in rows:
        pdata = "-" if r["pdata"] is None else int(r["pdata"])
        print(f"{r['name']:<{width}}  {r['rva']:>12}  {r['section']:<10} "
              f"pdata={pdata}  {r['bytes']:<24}  {r['verdict']}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")


def cmd_thunk(pe: PE, args) -> None:
    final, chain = follow_thunk(pe, args.rva, args.depth)
    pretty = " -> ".join(f"0x{c:X}" for c in chain)
    print(f"{pretty}\nreal target: 0x{final:X}   bytes: {hexbytes(pe.read(final, 12))}")


def cmd_disasm(pe: PE, args) -> None:
    try:
        import capstone  # noqa: F401
    except ImportError:
        raw = pe.read(args.rva, args.length)
        print(f"capstone missing; raw bytes at 0x{args.rva:X}: {hexbytes(raw)}")
        return
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if pe.is64 else capstone.CS_MODE_32)
    blob = pe.read(args.rva, args.length)
    for ins in md.disasm(blob, args.rva):
        print(f"0x{ins.address:08X}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")


SLOT_REF = re.compile(r"\b_?DAT_([0-9A-Fa-f]{6,16})\b")


def cmd_slotmap(pe: PE, args) -> None:
    """Dump qword slots holding code RVAs, plus which source lines reference them.

    A second tool's decompiled code stores every game function pointer as a data slot
    (``DAT_1801fa070`` etc). Mapping slot -> RVA -> referencing module turns an unknown
    binary into a labelled RVA table without touching the game.
    """
    refs: dict[int, list[str]] = {}
    if args.src:
        for f in sorted(Path(args.src).rglob("*.c")):
            for lineno, line in enumerate(
                    f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for m in SLOT_REF.finditer(line):
                    addr = int(m.group(1), 16)
                    refs.setdefault(addr, []).append(f"{f.stem}:{lineno}")

    # A section's virtual size is often far larger than its file-backed raw size: the
    # zero-filled tail holds runtime-initialised slots that do not exist on disk. Say so
    # instead of reporting an empty sweep.
    backed = 0
    for slot in range(args.start, args.end, args.step):
        if pe.offset_of(slot) is not None:
            backed += 1
    if backed == 0:
        print(f"range 0x{args.start:X}..0x{args.end:X} is not backed by file bytes "
              f"(zero-filled tail); nothing to read", file=sys.stderr)

    starts = pe.function_starts() or set()
    rows = []
    for slot in range(args.start, args.end, args.step):
        val = pe.read_ptr(slot)
        if not val:
            continue
        looks_rva = val < 0x20000000 and pe.in_code(val)
        if not looks_rva:
            continue
        final, chain = follow_thunk(pe, val)
        rows.append({
            "slot": f"0x{slot:X}",
            "rva": f"0x{val:X}",
            "final": f"0x{final:X}",
            "thunk": len(chain) > 1,
            "pdata": val in starts,
            "bytes": hexbytes(pe.read(final, 8)),
            "refs": refs.get(slot, []),
        })

    labelled = [r for r in rows if r["refs"]]
    out = args.json
    if out:
        Path(out).write_text(json.dumps(rows, indent=1), encoding="utf-8")
    print(f"{len(rows)} slots hold code RVAs; {len(labelled)} are referenced by sources")
    if rows and not labelled:
        print("hint: pass --src <decompiled dir> to label slots by the code that reads them")
    for r in labelled:
        print(f"{r['slot']:>14}  {r['rva']:>12}  {'thunk->'+r['final'] if r['thunk'] else '':'':<20}"
              f"  {r['refs'][0]}")


def main() -> None:
    ap = argparse.ArgumentParser(description="read-only PE inspector for offset work")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sections")
    p.add_argument("pe")
    p.set_defaults(fn=cmd_sections)

    p = sub.add_parser("verify")
    p.add_argument("pe")
    p.add_argument("spec", help='file with "name=rva" lines, or - for stdin')
    p.add_argument("--json", help="write the report as JSON here")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("thunk")
    p.add_argument("pe")
    p.add_argument("rva", type=lambda v: int(v, 0))
    p.add_argument("--depth", type=int, default=4)
    p.set_defaults(fn=cmd_thunk)

    p = sub.add_parser("disasm")
    p.add_argument("pe")
    p.add_argument("rva", type=lambda v: int(v, 0))
    p.add_argument("--len", dest="length", type=int, default=128)
    p.set_defaults(fn=cmd_disasm)

    p = sub.add_parser("slotmap")
    p.add_argument("pe")
    p.add_argument("start", type=lambda v: int(v, 0))
    p.add_argument("end", type=lambda v: int(v, 0))
    p.add_argument("--step", type=int, default=8)
    p.add_argument("--src", help="directory with decompiled .c files")
    p.add_argument("--json", help="write slot table here")
    p.set_defaults(fn=cmd_slotmap)

    args = ap.parse_args()
    pe = PE(args.pe)
    args.fn(pe, args)


if __name__ == "__main__":
    main()
