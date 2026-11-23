"""Find direct CALL/JMP xrefs to a target VA in GenshinImpact.exe (7.2)."""
import struct
import sys

import pefile

EXE = r"C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe"
target = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x141634160

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
