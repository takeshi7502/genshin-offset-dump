"""Ordinal/prefix name recovery with confidence tiers."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OLD = r"D:\GENSHIN\dump\dump.cs"
NEW = os.path.join(HERE, "dump_offsets_v2.cs")
OUT = os.path.join(HERE, "method_names2.json")
CLASS_RE = re.compile(r"^class\s+([^\s/]+)")
RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")


def parse(path, limit=None):
    classes = {}
    cur = None
    pending = None
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = CLASS_RE.match(line)
            if m:
                cur = m.group(1)
                classes.setdefault(cur, [])
                pending = None
                continue
            if cur is None:
                continue
            m = RVA_RE.search(line)
            if m:
                pending = m.group(1).upper()
                continue
            if pending and not line.startswith("\t//") and "(" in line:
                name = line.strip().split("(")[0].split()[-1]
                classes[cur].append({"rva": pending, "name": name})
                pending = None
    return classes


def main():
    old = parse(OLD)
    new = parse(NEW)
    result = {}
    stats = {"exact": 0, "prefix": 0}
    for cls, nm in new.items():
        if cls not in old or not nm:
            continue
        om = old[cls]
        n = min(len(nm), len(om))
        if len(nm) == len(om):
            conf = "exact"
            stats["exact"] += 1
        elif len(nm) < len(om) and n >= 1:
            conf = "prefix"
            stats["prefix"] += 1
        else:
            continue
        result[cls] = {"confidence": conf, "new_count": len(nm), "old_count": len(om),
                       "pairs": [{"rva": nm[i]["rva"], "name": om[i]["name"], "old_rva": om[i]["rva"]}
                                 for i in range(n)]}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    print("stats", stats, "classes", len(result),
          "pairs", sum(len(v["pairs"]) for v in result.values()))

    keys = ["dohit", "calcdamage", "sethp", "checktarget", "humanoidmove", "entitymanager",
            "levelssync", "levelsync", "skillcd", "landinner", "playerprop", "safedouble",
            "getposition", "setposition", "monobehaviour", "lateupdate", "tick", "entitymove",
            "motioninfo", "handleinput", "attackspeed", "stamina", "godmode", "noclip", "damage"]
    hits = []
    for cls, d in result.items():
        for p in d["pairs"]:
            low = p["name"].lower()
            if any(k in low for k in keys):
                hits.append((cls, d["confidence"], p["name"], p["rva"], p["old_rva"]))
    print("feature-ish hits:", len(hits))
    for h in hits[:120]:
        print(" ", h)


if __name__ == "__main__":
    main()
