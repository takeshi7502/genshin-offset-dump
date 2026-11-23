"""
Static IL2CPP API offset scanner for Genshin Impact (article method).

Finds the marker strings used by rumi.dev's IL2CPP runtime-dump write-up inside
GenshinImpact.exe, maps them to RVAs, then scans executable sections for
RIP-relative instructions that reference those strings. The containing function
is the inlined/obfuscated IL2CPP API we want.

Output: offsets_candidates.json + console report.
"""
import json
import os
import struct
import sys

import pefile

EXE = r"C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe"
OUT_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offsets_candidates.json")

# Exact marker strings from the article / libil2cpp source.
MARKERS = {
    "GetTypeInfoFromTypeDefinitionIndex": b"because generic types cannot have explicit layout.",
    "class_get_name_namespace": b"must be instantiated using the ScriptableObject.CreateInstance method instead of new %s.",
    "method_get_name": b"Script error (%s): %s.\n",
    "field_get_name": b"value__",
    "get_methods_ctor": b"ConstructorInfo",
    "get_type_info_generic": b"Generic type definition",
    "class_get_fields": b"FieldInfo",
}

REX_RANGE = range(0x40, 0x50)
# One-byte opcodes that commonly take a modrm byte with a RIP-relative operand.
OPS_1 = {0x8D, 0x8B, 0x89, 0x83, 0x85, 0x39, 0x3B, 0xC7, 0xA3, 0xA1,
         0x0F, 0x80, 0x81, 0xF7, 0x38, 0x3A, 0x88, 0x8A, 0xC6, 0xFE, 0xFF}
OPS_2 = {0xB6, 0xB7, 0xBE, 0xBF, 0xAF, 0x1F, 0x05, 0x0D}  # after 0F escape


def file_offset_to_rva(pe, off):
    for s in pe.sections:
        start = s.PointerToRawData
        end = start + s.SizeOfRawData
        if start <= off < end:
            return s.VirtualAddress + (off - start)
    return None


def rva_to_file_offset(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None


def find_marker_rvas(data, pe):
    found = {}
    for name, needle in MARKERS.items():
        rvas = []
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            rva = file_offset_to_rva(pe, i)
            if rva is not None:
                rvas.append(rva)
            start = i + 1
            if len(rvas) > 64:
                break
        found[name] = {"needle": needle.decode("utf-8", "replace"), "rvas": rvas}
    return found


def pdata_function_starts(pe):
    """Return sorted list of function start RVAs from .pdata (exception table)."""
    starts = set()
    try:
        exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
        if exc.VirtualAddress and exc.Size:
            off = rva_to_file_offset(pe, exc.VirtualAddress)
            if off is not None:
                for i in range(exc.Size // 12):
                    begin, end, unwind = struct.unpack_from("<III", data, off + i * 12)
                    if 0x140000000 > begin > 0x1000:
                        starts.add(begin)
    except Exception as e:
        print("[!] pdata parse:", e)
    return sorted(starts)


def containing_function(func_starts, rva):
    """Bisect the .pdata start list for the greatest start <= rva."""
    import bisect
    idx = bisect.bisect_right(func_starts, rva) - 1
    return func_starts[idx] if idx >= 0 else None


def backward_function_start(data, pe, instr_rva, limit=0x400):
    """Fallback: walk back to an int3/ret aligned boundary."""
    off = rva_to_file_offset(pe, instr_rva)
    if off is None:
        return None
    start_off = max(0, off - limit)
    pos = off
    while pos > start_off:
        pos -= 1
        b = data[pos]
        if b in (0xCC, 0xC3):
            cand = file_offset_to_rva(pe, pos + 1)
            if cand is not None and (instr_rva - cand) < limit:
                return cand
    return None


def scan_xrefs(data, pe, target_rvas, func_starts):
    """Scan executable sections for RIP-relative refs to any target RVA."""
    target_set = set(target_rvas)
    results = []
    exe_sections = [s for s in pe.sections if s.IMAGE_SCN_MEM_EXECUTE]
    for s in exe_sections:
        base_rva = s.VirtualAddress
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        n = len(raw)

        def check(disp_pos, instr_start, end_len):
            if disp_pos + 4 > n:
                return
            disp = struct.unpack_from("<i", raw, disp_pos)[0]
            target = base_rva + disp_pos + 4 + disp
            if target in target_set:
                instr_rva = base_rva + instr_start
                func = containing_function(func_starts, instr_rva) or \
                       backward_function_start(data, pe, instr_rva)
                results.append({
                    "instr_rva": instr_rva,
                    "function_rva": func,
                    "target_rva": target,
                    "section": s.Name.decode("utf-8", "replace").rstrip("\x00"),
                })

        i = 0
        while i < n - 8:
            b = raw[i]
            # [REX] opcode modrm disp32
            if b in REX_RANGE and raw[i + 1] in OPS_1 and (raw[i + 2] & 0xC7) == 0x05:
                check(i + 3, i, 7)
            # plain opcode modrm disp32 (no REX)
            elif b in OPS_1 and b != 0x0F and (raw[i + 1] & 0xC7) == 0x05:
                check(i + 2, i, 6)
            # [REX] 0F opcode modrm disp32
            elif b in REX_RANGE and raw[i + 1] == 0x0F and raw[i + 2] in OPS_2 \
                    and (raw[i + 3] & 0xC7) == 0x05:
                check(i + 4, i, 8)
            # 0F opcode modrm disp32 (no REX)
            elif b == 0x0F and raw[i + 1] in OPS_2 and (raw[i + 2] & 0xC7) == 0x05:
                check(i + 3, i, 7)
            i += 1
    # de-duplicate
    uniq = {}
    for r in results:
        uniq[(r["instr_rva"], r["target_rva"])] = r
    return list(uniq.values())


def scan_absolute_refs(data, pe, target_rvas, image_base, func_starts):
    """Find mov reg, imm64 / mov reg, imm32 instructions loading a marker VA."""
    va_to_name = {}
    for rva in target_rvas:
        va_to_name[image_base + rva] = rva
    low_to_rva = {}
    for rva in target_rvas:
        low_to_rva.setdefault((image_base + rva) & 0xFFFFFFFF, []).append(rva)

    results = []
    for s in pe.sections:
        if not s.IMAGE_SCN_MEM_EXECUTE:
            continue
        base_rva = s.VirtualAddress
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        n = len(raw)
        i = 0
        while i < n - 12:
            b = raw[i]
            # 48 B8+r imm64  (movabs reg, imm64)
            if b in (0x48, 0x49) and 0xB8 <= raw[i + 1] <= 0xBF:
                va = struct.unpack_from("<Q", raw, i + 2)[0]
                if va in va_to_name:
                    instr_rva = base_rva + i
                    func = containing_function(func_starts, instr_rva) or \
                           backward_function_start(data, pe, instr_rva)
                    results.append({"instr_rva": instr_rva, "function_rva": func,
                                    "target_rva": va_to_name[va], "kind": "movabs64",
                                    "section": s.Name.decode("utf-8", "replace").rstrip("\x00")})
            # 48 C7 C0+r imm32 (sign-extended mov reg, imm32)
            elif b in (0x48, 0x49) and raw[i + 1] == 0xC7 and 0xC0 <= raw[i + 2] <= 0xFF:
                val = struct.unpack_from("<i", raw, i + 3)[0] & 0xFFFFFFFF
                if val in low_to_rva:
                    instr_rva = base_rva + i
                    func = containing_function(func_starts, instr_rva) or \
                           backward_function_start(data, pe, instr_rva)
                    for rva in low_to_rva[val]:
                        results.append({"instr_rva": instr_rva, "function_rva": func,
                                        "target_rva": rva, "kind": "mov_imm32",
                                        "section": s.Name.decode("utf-8", "replace").rstrip("\x00")})
            i += 1
    uniq = {}
    for r in results:
        uniq[(r["instr_rva"], r["target_rva"], r["kind"])] = r
    return list(uniq.values())


def main():
    global data
    print("=" * 64)
    print("[+] Genshin IL2CPP static offset scanner")
    print("=" * 64)
    with open(EXE, "rb") as f:
        data = f.read()
    print(f"[+] Loaded {len(data):,} bytes from {EXE}")

    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]
    ])
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"[+] ImageBase: 0x{image_base:x}")

    func_starts = pdata_function_starts(pe)
    print(f"[+] .pdata function starts: {len(func_starts):,}")

    markers = find_marker_rvas(data, pe)
    all_rvas = []
    for name, info in markers.items():
        print(f"\n[*] {name}: {len(info['rvas'])} hit(s)")
        for rva in info["rvas"][:12]:
            print(f"      RVA 0x{rva:X}  -> VA 0x{image_base + rva:X}")
            all_rvas.append(rva)

    print(f"\n[*] Scanning executable sections for xrefs to {len(all_rvas)} marker RVAs...")
    xrefs = scan_xrefs(data, pe, all_rvas, func_starts)
    print(f"[+] Found {len(xrefs)} RIP-relative xref instruction(s)")
    abs_refs = scan_absolute_refs(data, pe, all_rvas, image_base, func_starts)
    print(f"[+] Found {len(abs_refs)} absolute-immediate xref instruction(s)")
    xrefs.extend(abs_refs)

    # Group by containing function
    groups = {}
    for x in xrefs:
        key = x["function_rva"]
        groups.setdefault(key, []).append(x)

    report = {
        "exe": EXE,
        "image_base": hex(image_base),
        "markers": markers,
        "xref_count": len(xrefs),
        "function_candidates": [],
    }
    print("\n" + "=" * 64)
    print("[+] Candidate functions (RVA -> IDA VA):")
    for frva, xs in sorted(groups.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
        if frva is None:
            continue
        targets = sorted(set(x["target_rva"] for x in xs))
        print(f"  0x{frva:X}  (VA 0x{image_base + frva:X})  xrefs={len(xs)}  targets={[hex(t) for t in targets]}")
        report["function_candidates"].append({
            "function_rva": hex(frva),
            "function_va": hex(image_base + frva),
            "xrefs": xs,
        })

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Saved {OUT_JSON}")


if __name__ == "__main__":
    main()
