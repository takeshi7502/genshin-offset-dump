import os
import sys

IDA = _require_path(os.environ.get("IDA_HOME", ""), "IDA install dir", "IDA_HOME")
sys.path.insert(0, os.path.join(IDA, "idalib", "python"))
os.environ["IDADIR"] = IDA

import idapro  # noqa
import ida_bytes  # noqa

DB = _require_path(os.environ.get("OLD_IDA_DB", ""), "IDA database", "OLD_IDA_DB")
VA = 0x141591C50  # 0x140000000 + 0x11591C50

print("[+] opening database ...", flush=True)
idapro.open_database(DB, run_auto_analysis=False)
print("[+] opened", flush=True)
data = ida_bytes.get_bytes(VA, 512)
print("[+] bytes:", data.hex() if data else None, flush=True)
OUT = os.environ.get("OUT_BIN", "target_func.bin")
with open(OUT, "wb") as f:
    f.write(data or b"")
idapro.close_database()
print("[+] done", flush=True)
