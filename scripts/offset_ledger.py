#!/usr/bin/env python3
"""offset_ledger.py - durable evidence ledger for offset work.

Every offset you keep must carry *how far* it was verified. Without that record the
next session re-does the same work, or worse, ships an unverified number.

Usage
-----
  # register / update one entry
  offset_ledger.py set ledger.json --name SetHP --rva 0x1086C7E0 \
      --kind code --level L2 --source "pe_tool verify" --note "pdata ok, not a thunk"

  # bump a level after a live test
  offset_ledger.py bump ledger.json --name SetHP --level L4 --note "hp dropped in game"

  # inspect
  offset_ledger.py show ledger.json            # markdown table, grouped by kind
  offset_ledger.py stale ledger.json --patch 7.2

Levels (do not skip):
  L0  address exists inside a mapped code/data section of the target build
  L1  real function entry (.pdata / symbol table), not mid-instruction
  L2  not a thunk; prologue sane; argument shape read from call sites in the disassembly
  L3  called from the correct thread with the correct arguments without faulting
  L4  produces the intended observable effect in the running game
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

LEVELS = ["L0", "L1", "L2", "L3", "L4"]


def load(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8-sig"))
    return {"entries": {}}


def save(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def cmd_set(args) -> None:
    data = load(Path(args.ledger))
    entry = data["entries"].get(args.name, {})
    entry.update({
        "name": args.name,
        "kind": args.kind,
        "rva": args.rva,
        "level": args.level,
        "source": args.source or entry.get("source", ""),
        "patch": args.patch or entry.get("patch", ""),
        "updated": now(),
    })
    if args.note:
        entry.setdefault("notes", []).append(f"{now()} {args.note}")
    entry.setdefault("notes", [])
    data["entries"][args.name] = entry
    save(Path(args.ledger), data)
    print(f"{args.name}: {args.level} {args.rva} ({args.kind})")


def cmd_bump(args) -> None:
    data = load(Path(args.ledger))
    entry = data["entries"].get(args.name)
    if not entry:
        raise SystemExit(f"unknown entry {args.name}")
    cur = entry.get("level", "L0")
    if LEVELS.index(args.level) < LEVELS.index(cur):
        raise SystemExit(f"refusing to lower {args.name} from {cur} to {args.level}")
    entry["level"] = args.level
    entry["updated"] = now()
    if args.note:
        entry.setdefault("notes", []).append(f"{now()} {args.note}")
    save(Path(args.ledger), data)
    print(f"{args.name}: {cur} -> {args.level}")


def cmd_show(args) -> None:
    data = load(Path(args.ledger))
    entries = sorted(data["entries"].values(), key=lambda e: (e.get("kind", ""), e["name"]))
    if not entries:
        print("(empty ledger)")
        return
    print("| name | kind | rva | level | patch | updated |")
    print("|---|---|---|---|---|---|")
    for e in entries:
        print(f"| {e['name']} | {e.get('kind','')} | `{e.get('rva','')}` | "
              f"{e.get('level','L0')} | {e.get('patch','')} | {e.get('updated','')[:10]} |")

    low = [e for e in entries if LEVELS.index(e.get("level", "L0")) < 2]
    if low:
        print(f"\n**{len(low)} entries below L2 - do not wire these yet:** " +
              ", ".join(e["name"] for e in low))


def cmd_stale(args) -> None:
    data = load(Path(args.ledger))
    stale = [e for e in data["entries"].values()
             if args.patch and e.get("patch") and e["patch"] != args.patch]
    for e in stale:
        print(f"{e['name']}: verified on patch {e['patch']}, current target {args.patch} "
              f"-> re-verify at L1/L2 before use")
    if not stale:
        print("nothing recorded for another patch")


def main() -> None:
    ap = argparse.ArgumentParser(description="evidence ledger for offsets")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("set")
    p.add_argument("ledger")
    p.add_argument("--name", required=True)
    p.add_argument("--rva", required=True)
    p.add_argument("--kind", default="code", choices=["code", "field", "slot", "chain"])
    p.add_argument("--level", default="L0", choices=LEVELS)
    p.add_argument("--source", default="")
    p.add_argument("--patch", default="")
    p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_set)

    p = sub.add_parser("bump")
    p.add_argument("ledger")
    p.add_argument("--name", required=True)
    p.add_argument("--level", required=True, choices=LEVELS)
    p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_bump)

    p = sub.add_parser("show")
    p.add_argument("ledger")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("stale")
    p.add_argument("ledger")
    p.add_argument("--patch", required=True)
    p.set_defaults(fn=cmd_stale)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
