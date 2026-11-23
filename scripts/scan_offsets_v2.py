"""Fast IL2CPP marker/xref scanner (range-aware) for GenshinImpact.exe."""
import bisect
import json
import os
import struct

import pefile

EXE = r"C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offsets_v2.json")

MARKERS = {
    "GetTypeInfoFromTypeDefinitionIndex": [
        b"because generic types cannot have explicit layout.",
    ],
    "class_get_name_namespace": [
        b"%s%s%s must be instantiated using the ScriptableObject.CreateInstance method instead of new %s.",
        b"must be instantiated using the ScriptableObject.CreateInstance method instead of new %s.",
        b"ScriptableObject.CreateInstance",
    ],
    "method_get_name": [
        b"Script error (%s): %s.\n",
        b"Script error (%s): %s.",
    ],
    "field_get_name": [
        b"value__",
    ],
    "get_methods_ctor": [
        b"ConstructorInfo",
    ],
    "get_fields_fieldinfo": [
        b"FieldInfo",
    ],
    "misc": [
        b"GenericParameterHandle",
        b"MethodInfo",
        b"Il2CppClass",
    ],
}

REXR = range(0x40, 0x50)
OPS1 = {0x8D, 0x8B, 0x89, 0x83, 0x85, 0x39, 0x3B, 0xC7, 0xA3, 0xA1,
        0xF7, 0x38, 0x3A, 0x88, 0x8A, 0xC6, 0xFE, 0xFF}
OPS2 = {0xB6, 0xB7, 0xBE, 0xBF, 0xAF, 0x1F, 0x05, 0x0D}


def main():
    with open(EXE, "rb") as f:
        data = f.read()
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    base = pe.OPTIONAL_HEADER.ImageBase

    def f2r(off):
        for s in pe.sections:
            if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
                return s.VirtualAddress + off - s.PointerToRawData
        return None

    # .pdata function starts
    starts = set()
    exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    off = f2r(exc.VirtualAddress)
    file_off = None
    for s in pe.sections:
        if s.VirtualAddress <= exc.VirtualAddress < s.VirtualAddress + s.Misc_VirtualSize:
            file_off = s.PointerToRawData + exc.VirtualAddress - s.VirtualAddress
            break
    if file_off:
        for i in range(exc.Size // 12):
            b, e, u = struct.unpack_from("<III", data, file_off + i * 12)
            if 0x1000 < b < 0xF0000000:
                starts.add(b)
    starts = sorted(starts)
    print(f"[+] .pdata functions: {len(starts):,}")

    markers = {}
    intervals = []
    for name, needles in MARKERS.items():
        hits = []
        for needle in needles:
            pos = 0
            while True:
                i = data.find(needle, pos)
                if i < 0:
                    break
                rva = f2r(i)
                if rva is not None:
                    hits.append({"rva": rva, "len": len(needle), "text": needle.decode("utf-8", "replace")})
                pos = i + 1
        # unique by rva
        seen = set()
        uniq = []
        for h in hits:
            if h["rva"] not in seen:
                seen.add(h["rva"])
                uniq.append(h)
        markers[name] = uniq
        for h in uniq:
            intervals.append((h["rva"] - 0x10, h["rva"] + h["len"] + 0x10, name, h))
        print(f"[*] {name}: {len(uniq)} hit(s) -> {[hex(h['rva']) for h in uniq[:8]]}")

    def nearest(rva):
        for lo, hi, name, h in intervals:
            if lo <= rva <= hi:
                return name, h
        return None, None

    results = []
    for s in pe.sections:
        if not s.IMAGE_SCN_MEM_EXECUTE:
            continue
        b_rva = s.VirtualAddress
        raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        n = len(raw)
        i = 0
        while i < n - 12:
            b = raw[i]
            disp = None
            if b in REXR and raw[i + 1] in OPS1 and (raw[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                end = i + 7
            elif b in OPS1 and b != 0x0F and (raw[i + 1] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 2)[0]
                end = i + 6
            elif b in REXR and raw[i + 1] == 0x0F and raw[i + 2] in OPS2 and (raw[i + 3] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 4)[0]
                end = i + 8
            elif b == 0x0F and raw[i + 1] in OPS2 and (raw[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", raw, i + 3)[0]
                end = i + 7
            if disp is not None:
                target = b_rva + end + disp
                name, h = nearest(target)
                if name:
                    i_rva = b_rva + i
                    idx = bisect.bisect_right(starts, i_rva) - 1
                    func = starts[idx] if idx >= 0 else None
                    results.append({
                        "marker": name,
                        "marker_rva": hex(h["rva"]),
                        "marker_text": h["text"][:80],
                        "target_rva": hex(target),
                        "instr_rva": hex(i_rva),
                        "function_rva": hex(func) if func else None,
                        "function_va": hex(base + func) if func else None,
                        "section": s.Name.decode("utf-8", "replace").rstrip("\x00"),
                    })
            i += 1

    uniq = {}
    for r in results:
        uniq[(r["marker"], r["instr_rva"], r["target_rva"])] = r
    results = sorted(uniq.values(), key=lambda x: (x["marker"], int(x["function_rva"] or "0", 16)))

    print(f"\n[+] xrefs: {len(results)}")
    for r in results:
        print(f"  {r['marker']:<38} instr {r['instr_rva']:>10} -> func {str(r['function_rva']):>12}  target {r['target_rva']}")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"image_base": hex(base), "markers": markers, "xrefs": results}, f, indent=2)
    print(f"[+] Saved {OUT}")


if __name__ == "__main__":
    main()
