"""Named offset recovery v2: relocation-masked bytecode matching 7.0 -> 7.2."""
import json
import os
import re
import struct
import sys

import pefile

def _require_path(value, what, env_name):
    """Resolve a path from argv/env, or stop with a usage line."""
    if value:
        p = Path(value)
        if p.exists():
            return str(p)
        raise SystemExit(f"{what} not found: {p}")
    raise SystemExit(
        f"usage: pass the {what} path as an argument or set {env_name}\n"
        f"  e.g.  python {Path(__file__).name} <{what}>")

HERE = os.path.dirname(os.path.abspath(__file__))
OLD_DUMP = _require_path(os.environ.get("OLD_DUMP", ""), "old dump.cs", "OLD_DUMP")
EXE = _require_path(os.environ.get("TARGET_PE", ""), "target executable", "TARGET_PE")
IDA_DB = _require_path(os.environ.get("OLD_IDA_DB", ""), "old IDA database", "OLD_IDA_DB")
OUT = os.path.join(HERE, "named_offsets_v2.json")
NLEN = 48
LIMIT = int(sys.argv[1]) if len(sys.argv) > 1 else 0


def normalize(buf):
    """Return (masked_bytes, mask) with reloc bytes zeroed and mask byte=1."""
    b = bytearray(buf)
    mask = bytearray(len(b))
    i = 0
    n = len(b)
    while i < n:
        op = b[i]
        # call/jmp rel32
        if op in (0xE8, 0xE9) and i + 5 <= n:
            for j in range(i + 1, i + 5):
                b[j] = 0; mask[j] = 1
            i += 5; continue
        # conditional jmp rel32 (0F 8x)
        if op == 0x0F and i + 1 < n and 0x80 <= b[i+1] <= 0x8F and i + 6 <= n:
            for j in range(i + 2, i + 6):
                b[j] = 0; mask[j] = 1
            i += 6; continue
        # REX + RIP-relative modrm (mod=00 rm=101)
        if 0x40 <= op <= 0x4F and i + 2 < n and (b[i+2] & 0xC7) == 0x05 and i + 7 <= n:
            for j in range(i + 3, i + 7):
                b[j] = 0; mask[j] = 1
            i += 7; continue
        # plain RIP-relative (opcode at i, modrm at i+1)
        if (b[i+1] & 0xC7) == 0x05 if i + 1 < n else False:
            if i + 6 <= n:
                for j in range(i + 2, i + 6):
                    b[j] = 0; mask[j] = 1
                i += 6; continue
        # movabs reg, imm64
        if 0x40 <= op <= 0x4F and i + 1 < n and 0xB8 <= b[i+1] <= 0xBF and i + 10 <= n:
            for j in range(i + 2, i + 10):
                b[j] = 0; mask[j] = 1
            i += 10; continue
        i += 1
    return bytes(b), bytes(mask)


def main():
    print("[+] parsing old dump ...", flush=True)
    info = {}
    cur = ""; pending = None
    with open(OLD_DUMP, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"^class\s+([^\s/]+)", line)
            if m:
                cur = m.group(1); continue
            m = re.search(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)", line)
            if m:
                pending = m.group(1); continue
            if pending and "(" in line and not line.startswith("\t//"):
                name = line.strip().split("(")[0].split()[-1]
                info[int(pending, 16)] = (cur, name); pending = None
    print(f"    {len(info)} methods", flush=True)
    items = list(info.items())
    if LIMIT: items = items[:LIMIT]

    print("[+] indexing 7.2 ...", flush=True)
    data = open(EXE, "rb").read()
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])

    def rva_to_off(rva):
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
                return s.PointerToRawData + rva - s.VirtualAddress
        return None

    exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    fo = rva_to_off(exc.VirtualAddress)
    starts = set()
    for i in range(exc.Size // 12):
        b, e, u = struct.unpack_from("<III", data, fo + i * 12)
        if 0x1000 < b < 0xF0000000: starts.add(b)
    starts = sorted(starts)
    index = {}
    for rva in starts:
        off = rva_to_off(rva)
        if off is None or off + NLEN > len(data): continue
        key = normalize(data[off:off + NLEN])
        index.setdefault(key, rva)
    print(f"    {len(starts)} funcs / {len(index)} sigs", flush=True)

    IDA = r"D:\PHAN_MEM\IDA 9.1 Pro"
    sys.path.insert(0, os.path.join(IDA, "idalib", "python"))
    os.environ["IDADIR"] = IDA
    import idapro, ida_bytes
    print("[+] opening IDA DB ...", flush=True)
    idapro.open_database(IDA_DB, run_auto_analysis=False)

    matches = {}
    for n, (rva70, (cls, name)) in enumerate(items, 1):
        try: b = ida_bytes.get_bytes(0x140000000 + rva70, NLEN)
        except Exception: b = None
        if b and len(b) == NLEN:
            rva72 = index.get(normalize(b))
            if rva72 is not None:
                matches[f"{cls}::{name}"] = {"class": cls, "name": name,
                                             "rva70": hex(rva70), "rva72": hex(rva72)}
        if n % 50000 == 0: print(f"    {n}/{len(items)} matched={len(matches)}", flush=True)
    idapro.close_database()
    with open(OUT, "w", encoding="utf-8") as f: json.dump(matches, f, indent=1)
    print(f"[+] DONE {len(matches)} -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
