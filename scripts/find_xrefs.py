"""Find direct CALL/JMP xrefs to a target VA in a PE.

Usage:  python find_xrefs.py <target.exe> [VA]
        TARGET_PE=<target.exe> python find_xrefs.py -- <VA>
"""
import os
import struct
import sys
from pathlib import Path

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

_args = [a for a in sys.argv[1:] if a != "--"]
_exe = _args[0] if _args and not _args[0].lower().startswith("0x") else os.environ.get("TARGET_PE", "")
EXE = _require_path(_exe, "target executable", "TARGET_PE")
_va = next((a for a in _args if a.lower().startswith("0x")), "0x141634160")
target = int(_va, 16)

data = open(EXE, "rb").read()
pe = pefile.PE(data=data, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
print(f"target VA 0x{target:x} RVA 0x{target-base:x}")

for s in pe.sections:
    if not s.IMAGE_SCN_MEM_EXECUTE:
        continue
    raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    n = len(raw)
    hits = []
    for i in range(n - 5):
        op = raw[i]
        if op == 0xE8 or op == 0xE9:  # call/jmp rel32
            rel = struct.unpack_from("<i", raw, i + 1)[0]
            src_rva = s.VirtualAddress + i
            dst_rva = src_rva + 5 + rel
            if base + dst_rva == target:
                hits.append(src_rva)
        elif op == 0x15 or op == 0x25:  # jmp/call [rip+disp32] (import thunks)
            pass
    if hits:
        print(f"[{s.Name.decode().rstrip(chr(0))}] {len(hits)} xref(s)")
        for h in hits[:50]:
            print(f"  caller RVA 0x{h:X}  VA 0x{base+h:X}")
