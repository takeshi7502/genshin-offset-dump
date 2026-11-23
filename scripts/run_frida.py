"""Attach Frida to a running GenshinImpact.exe, inject a script, collect logs.

Usage:
  python run_frida.py <script.js> [--pid PID] [--seconds N] [--candidates JSON]
"""
import argparse
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))


def on_message(message, data):
    if message["type"] == "send":
        print("[send]", message["payload"])
    elif message["type"] == "error":
        print("[error]", message.get("stack") or message.get("description"))
    else:
        print("[msg]", message)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--candidates", default="")
    ap.add_argument("--spawn", action="store_true")
    args = ap.parse_args()

    device = frida.get_local_device()
    if args.spawn:
        exe = r"C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe"
        pid = device.spawn([exe])
        print(f"[+] spawned pid={pid}")
    elif args.pid:
        pid = args.pid
    else:
        procs = [p for p in device.enumerate_processes() if p.name.lower() == "genshinimpact.exe"]
        if not procs:
            print("[-] game not running")
            sys.exit(1)
        pid = procs[0].pid
        print(f"[+] attaching pid={pid}")

    session = device.attach(pid)
    with open(os.path.join(HERE, args.script), "r", encoding="utf-8") as f:
        source = f.read()

    candidates = []
    if args.candidates:
        with open(args.candidates, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict) and "candidates" in data:
            candidates = data["candidates"]
    source = "const CANDIDATES = " + json.dumps(candidates) + ";\n" + source

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print(f"[+] loaded {args.script}, waiting {args.seconds}s ...")
    if args.spawn:
        device.resume(pid)
    time.sleep(args.seconds)
    try:
        session.detach()
    except Exception:
        pass
    print("[+] done")


if __name__ == "__main__":
    main()
