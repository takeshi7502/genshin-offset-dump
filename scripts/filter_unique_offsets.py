"""Drop name matches whose normalized signature is ambiguous among 7.2 functions."""
import json
import os
import struct

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
SRC = os.path.join(HERE, "named_offsets_verified.json")
OUT = os.path.join(HERE, "named_offsets_unique.json")
EXE = _require_path(os.environ.get("TARGET_PE", ""), "target executable", "TARGET_PE")
NLEN = 48


def normalize(buf):
    b = bytearray(buf); m = bytearray(len(b)); i = 0
    while i < len(b):
        op = b[i]
        if op in (0xE8, 0xE9) and i+5 <= len(b):
            for j in range(i+1, i+5): b[j]=0; m[j]=1
            i += 5; continue
        if op == 0x0F and i+1 < len(b) and 0x80 <= b[i+1] <= 0x8F and i+6 <= len(b):
            for j in range(i+2, i+6): b[j]=0; m[j]=1
            i += 6; continue
        if 0x40 <= op <= 0x4F and i+2 < len(b) and (b[i+2] & 0xC7)==0x05 and i+7 <= len(b):
            for j in range(i+3, i+7): b[j]=0; m[j]=1
            i += 7; continue
        if i+1 < len(b) and (b[i+1] & 0xC7)==0x05 and i+6 <= len(b):
            for j in range(i+2, i+6): b[j]=0; m[j]=1
            i += 6; continue
        if 0x40 <= op <= 0x4F and i+1 < len(b) and 0xB8 <= b[i+1] <= 0xBF and i+10 <= len(b):
            for j in range(i+2, i+10): b[j]=0; m[j]=1
            i += 10; continue
        i += 1
    return bytes(b), bytes(m)


def main():
    d = json.load(open(SRC, encoding="utf-8"))
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
    counts = {}
    for i in range(exc.Size // 12):
        b, e, u = struct.unpack_from("<III", data, fo + i * 12)
        if not (0x1000 < b < 0xF0000000):
            continue
        off = rva_to_off(b)
        if off is None or off + NLEN > len(data):
            continue
        key = normalize(data[off:off + NLEN])
        counts[key] = counts.get(key, 0) + 1

    out = {}
    for key, v in d.items():
        rva = int(v["rva72"], 16)
        off = rva_to_off(rva)
        if off is None:
            continue
        sig = normalize(data[off:off + NLEN])
        c = counts.get(sig, 0)
        if c == 1:
            out[key] = v
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(f"[+] unique matches: {len(out)}/{len(d)} -> {OUT}")


if __name__ == "__main__":
    main()
