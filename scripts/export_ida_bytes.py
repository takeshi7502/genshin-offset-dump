import os
import sys

IDA = r"D:\PHAN_MEM\IDA 9.1 Pro"
sys.path.insert(0, os.path.join(IDA, "idalib", "python"))
os.environ["IDADIR"] = IDA

import idapro  # noqa
import ida_bytes  # noqa

DB = r"D:\GENSHIN\dump\Genshin_v7.i64"
VA = 0x141591C50  # 0x140000000 + 0x11591C50

print("[+] opening database ...", flush=True)
idapro.open_database(DB, run_auto_analysis=False)
print("[+] opened", flush=True)
data = ida_bytes.get_bytes(VA, 512)
print("[+] bytes:", data.hex() if data else None, flush=True)
with open(r"D:\GENSHIN\dump7.2\target_func.bin", "wb") as f:
    f.write(data or b"")
idapro.close_database()
print("[+] done", flush=True)
