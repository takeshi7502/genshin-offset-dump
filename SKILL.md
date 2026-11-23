---
name: genshin-7x-offset-dump
description: Dump and recover IL2CPP class/method offsets for Genshin Impact 7.x on Windows (encrypted MHY metadata, hidden exports) using static marker scanning, Ghidra MCP, Frida runtime struct reversing, IDA Database bytecode matching across versions, and safe MinHook integration. Use when the task is to find RVAs for game functions, recover method names, or build/repair a Genshin offset dumper or hook DLL.
---

# Genshin 7.x — IL2CPP offset dump & recovery

Skill này ghi lại **toàn bộ quy trình đã chạy thành công** trên Genshin 7.2.0 (Windows, x64).
Mọi bước đều có script thật trong `scripts/`. Đọc hết phần "Bẫy" trước khi hook.

---

## 0. Sự thật nền tảng (đọc trước, tránh mất vài ngày)

| Điều | Thực tế trên 7.2.0 |
|---|---|
| `global-metadata.dat` | Magic `4D 48 59 00` = `"MHY\0"` → **encrypted**, không phải IL2CPP chuẩn. Il2CppDumper/MetadataConverter2 bản cũ **fail** (`Invalid signature: 0x...`). |
| Export IL2CPP | Từ 3.2 **đã bị ẩn hết** (`il2cpp_*` không còn export). |
| `GameAssembly.dll` | **Không còn**. Code IL2CPP compile thẳng vào `GenshinImpact.exe` (~451 MB). |
| Metadata trong RAM | **Không tìm thấy plaintext** (scan `AF1BF1FF`, `FAB11BAF`, `MHY\0` → 0 hit). Nghĩa là header bị xử lý riêng, đừng mất thời gian scan magic. |
| Tên method trong RAM | **Không có plaintext**. Scan `DoHitEntity`, `CalcDamage`, `VCHumanoidMove`… → 0 hit. Metadata string table bị mã hoá. |
| `il2cpp_class_get_name` / `method_get_name` | **Không tìm được bằng xref string**. Các hàm quanh marker string đều là error formatter, gọi vào là AV. Đừng phí thời gian. |
| `s_TypeInfoTable` | Vẫn tồn tại, là **global pointer** trong `.data`, không phải symbol. Tìm qua decompile hàm getter. |
| Cấu trúc class | **Shuffled**: `klass = TypeInfo + 0x08`, `name = *(klass + 0x88)`, method entry nằm **inline tại `klass + 0x100`, stride `0x38`**. `klass+0x18` là **typedef index**, KHÔNG phải method count. |

> Kết luận: chỉ có 3 đường sống — (A) static marker scan + Ghidra, (B) Frida gọi API runtime,
> (C) bytecode matching từ IDA DB của bản cũ. Phải dùng **cả 3**.

---

## 1. Inventory công cụ (đường dẫn thật trên máy này)

| Tool | Path | Dùng để |
|---|---|---|
| Ghidra 12.1.4 + GhidraMCP 7.0.0 | `C:\Tools\ghidra_12.1.4_PUBLIC\ghidraRun.bat`, plugin HTTP `127.0.0.1:8089` | decompile, xref, tìm hàm quanh string |
| JDK 21 | `C:\Tools\jdk-21.0.13+9` | Ghidra |
| IDA Pro 9.1 + `idalib` | `D:\PHAN_MEM\IDA 9.1 Pro\idalib\python` | export bytecode hàm bản cũ |
| IDA DB bản cũ | `D:\GENSHIN\dump\Genshin_v7.i64` | nguồn bytecode để match |
| Frida (python) | `python -m pip show frida` (16.5.9) | attach/spawn, gọi API runtime |
| Python packages | `pefile`, `capstone`, `frida`, `pycryptodome` | scan PE, disasm, runtime |
| VS 2022 Community | `...\Common7\Tools\VsDevCmd.bat` | build DLL hook (cl.exe) |
| MinHook | `vendor\minhook\lib\libMinHook.x64.lib` | hook |
| ImGui 1.92.x | `vendor\imgui` | overlay/launcher GUI |

Biến môi trường cho idalib:
```powershell
$env:PYTHONPATH='D:\PHAN_MEM\IDA 9.1 Pro\idalib\python'
$env:IDADIR='D:\PHAN_MEM\IDA 9.1 Pro'
```

---

## 2. Phase 0 — Recon

```powershell
# version game
Get-Content 'C:\Program Files\HoYoPlay\games\Genshin Impact game\config.ini'
# file chính
Get-ChildItem 'C:\Program Files\HoYoPlay\games\Genshin Impact game' | ft Name,Length
```

Cần lấy: `game_version` (vd `7.2.0`), kích thước `GenshinImpact.exe`, và xác nhận
`GenshinImpact_Data\Managed\Metadata\global-metadata.dat` có magic `4D 48 59 00`.

**ImageBase của exe = `0x140000000`.** Mọi "RVA" trong tài liệu = `VA - 0x140000000`.

---

## 3. Phase 1 — Static marker scan (không cần chạy game)

Mục tiêu: tìm RVA của các string đặc trưng, rồi tìm hàm reference chúng.

### 3.1 Marker string đã biết (7.2.0)

| API đích | String marker | RVA string |
|---|---|---|
| `MetadataCache::GetTypeInfoFromTypeDefinitionIndex` | `because generic types cannot have explicit layout.` | `0x3AD08AB` |
| `Class::GetName` / `GetNamespace` | `must be instantiated using the ScriptableObject.CreateInstance method instead of new %s.` | `0x3B80B90` |
| `method name` path | `Script error (%s): %s.\n` | `0x3B5DBD8` |
| field enum | `value__` | `0x3AC1756` |
| method ctor | `ConstructorInfo` | `0x3AA3AE2` |
| field info | `FieldInfo` | `0x3AA3E9F` |

### 3.2 Chạy

```powershell
python scripts\scan_offsets_v2.py      # range-aware, RIP-relative + imm
python scripts\scan_offsets_static.py  # exact match + .pdata function mapping
```

Script làm gì:
1. `pefile` load exe, đọc `.pdata` (exception directory) → danh sách **1.19M function start**.
2. Tìm string marker → RVA.
3. Quét mọi section executable tìm instruction RIP-relative (`REX + opcode + modrm(0x05) + disp32`)
   và `movabs imm64` trỏ tới string (cho phép ±0x10 để bắt string bị split).
4. Map instruction → function start gần nhất bằng bisect trên `.pdata`.
5. Ghi `offsets_v2.json`.

> **Chỉ tin function start từ `.pdata`**, đừng dùng heuristic "quét ngược tới 0xCC" — trên binary này
> nó trả về giữa hàm.

### 3.3 Giới hạn của bước này
Trên 7.2, marker scan tìm được nhiều hàm nhưng **không phân biệt được hàm nào là API thật**.
Vì vậy bước này chỉ để **lấy ứng viên**, phải validate bằng runtime (Phase 3).

---

## 4. Phase 2 — Ghidra MCP (decompile + xref)

### 4.1 Import exe (chỉ 1 lần, KHÔNG bật auto-analysis cho nhanh)

```powershell
New-Item -ItemType Directory -Force -Path 'D:\GENSHIN\dump7.2\ghidra_proj' | Out-Null
& 'C:\Tools\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat' `
  'D:\GENSHIN\dump7.2\ghidra_proj' 'GI72' `
  -import 'C:\Program Files\HoYoPlay\games\Genshin Impact game\GenshinImpact.exe' `
  -noanalysis
```

`.pdata` được Ghidra dùng để tạo **1.14M function** ngay cả khi không auto-analyze. Đủ để decompile.

### 4.2 Bật MCP

```powershell
Start-Process -FilePath 'C:\Tools\ghidra_12.1.4_PUBLIC\ghidraRun.bat' `
  -ArgumentList 'D:\GENSHIN\dump7.2\ghidra_proj\GI72.gpr'
```
Kiểm tra: `curl http://127.0.0.1:8089/check_connection`.
Nếu MCP client báo "no instance": gọi `connect_instance({project:"GI72"})` rồi `open_program({path:"/GenshinImpact.exe"})`.

### 4.3 Dùng

```
analyze_function_complete({function:"0x14051D860"})
search_strings({search_term:"value__"})        # sẽ rỗng nếu chưa auto-analyze
get_xrefs_to({addresses:"0x143AD08AB"})        # cũng rỗng nếu chưa analyze
```

> **Bẫy:** khi chưa auto-analyze, `search_strings` và `get_xrefs_to` **trả rỗng** dù string có thật.
> Vẫn decompile được từng hàm theo address (nhờ `.pdata`). Đừng kết luận "không có xref".
> Muốn string/xref đầy đủ thì phải chạy `run_analysis` (rất lâu với 451 MB).

### 4.4 Cách đọc decompile để tìm đúng API

Ví dụ tìm `GetTypeInfoFromTypeDefinitionIndex`:
1. String `because generic types cannot have explicit layout.` ở RVA `0x3AD08AB`.
2. Scan static ra nhiều ứng viên, trong đó có hàm đọc `lRam...8f20 + index*8` và gọi
   `FUN_...527830` → đúng là MetadataCache.
3. Decompile `FUN_140527E20`: thấy `*(qword*)(table + idx*8)` → đây là hàm trả `TypeInfo*`.

**Quy tắc vàng:** hàm trả `TypeInfo*` phải có pattern
`mov rax, [rip+X]` → `mov rax, [rax + rcx*8]` → `ret` (hoặc cache table).
Ứng viên nào có XOR/sub constant lạ → nhiều khả năng không phải.

---

## 5. Phase 3 — Frida: validate & reverse struct runtime

### 5.1 Chạy game + attach

```powershell
# spawn (game chưa chạy)
python scripts\run_frida.py frida_dump_clean.js --spawn --seconds 180
# attach (game đang chạy)
python scripts\run_frida.py frida_hook_observe.js --pid <PID> --seconds 60
```

`run_frida.py` inject biến `CANDIDATES` từ file JSON trước khi load script,
nên có thể truyền danh sách RVA mà không sửa JS.

### 5.2 Validate một API có đúng không

Dùng `frida_validate.js` / `frida_test_apis3.js`:
- Gọi hàm với `int` 0,1,2,10 → nếu trả pointer đọc được và `+0x20` có tên → đúng.
- **Bắt buộc dùng đúng kiểu object**: `GetTypeInfo` nhận `int`; `class_get_*` nhận `klass` (KHÔNG phải `TypeInfo`).

Kết quả đã xác nhận trên 7.2.0:
```
GetTypeInfoFromTypeDefinitionIndex = RVA 0x527E20
  f(0) = 0x500010aefb8  (TypeInfo*)
```

### 5.3 Cấu trúc runtime đã reverse được (7.2.0)

```
TypeInfo* ti = GetTypeInfo(i);        // RVA 0x527E20
klass        = *(void**)(ti + 0x08);
name         = *(char**)(klass + 0x88);     // "Locale", "CodePointIndexer"
typedefIndex = *(u64*)(klass + 0x18);       // KHÔNG phải method count
methods      = inline tại klass + 0x100, mỗi entry 0x38 byte
codeRVA      = *(void**)(entry + 0x00) - gameBase
```

Kiểm chứng: `GetTypeInfo(0)` → `klass=0x500010aeeb0`, name `"Locale"`;
`GetTypeInfo(100)` → `"CodePointIndexer"`; `GetTypeInfo(1000)` → `"Array"`.

> **Bẫy cực quan trọng:** `klass+0x30` trông như pointer array nhưng thực chất là vùng
> overlap. Dùng `klass+0x30` + stride `0x38` sẽ cho RVA rác (66 triệu dòng sau 30k class).
> **Phải dùng `klass + 0x100` + stride `0x38`.**
> `klass+0x18` là typedef index (513, 516, 519…) — dùng làm method count sẽ sinh rác.

### 5.4 Dump sạch

```powershell
python scripts\run_frida.py frida_dump_clean.js --spawn --seconds 200
# -> dump_clean.cs : ~200k class / ~494k method RVA
```

Kiểm tra: chỉ giữ code pointer nằm trong **code section**:
```
.text  : 0x1000 .. 0x21D2200
il2cpp : 0x6D2B000 .. 0x1A400000
```
Đây là 2 section chứa code của Genshin 7.2 (lấy bằng `pefile`).

### 5.5 Nếu cần dump có kiểm soát (không treo)
Tuyệt đối **không** gọi `GetTypeInfo` từ thread phụ lúc game đang load/đang vào world.
Chỉ scan khi:
- game đã ở menu chính hoặc đã vào world,
- và nên chạy async (thread riêng trả kết quả dần), không block thread render.

---

## 6. Phase 4 — Phục hồi TÊN method (bytecode matching)

Vì tên method bị mã hoá, không đọc trực tiếp được. Cách duy nhất đã chứng minh hiệu quả:
**so khớp bytecode hàm giữa IDA DB bản cũ và binary bản mới.**

### 6.1 Ý tưởng
- Bản cũ (7.0) có `Genshin_v7.i64` + `dump.cs` (có tên + RVA).
- Bản mới (7.2) có binary nhưng không tên.
- Hàm không đổi → bytecode giống nhau → match được.

### 6.2 Pipeline

```powershell
# B1: index function start của 7.2 từ .pdata + normalized signature
# B2: mở IDA DB, export 48 byte đầu mỗi hàm 7.0, so khớp
$env:PYTHONPATH='D:\PHAN_MEM\IDA 9.1 Pro\idalib\python'
$env:IDADIR='D:\PHAN_MEM\IDA 9.1 Pro'
python scripts\build_named_offsets_v2.py 0
# -> named_offsets_v2.json  (16.292 match)
```

### 6.3 Normalize (bắt buộc, nếu không sẽ 0 match)

Mask các byte phụ thuộc vị trí trước khi so sánh:
- `E8/E9 rel32` (call/jmp) → mask 4 byte sau opcode
- `0F 8x rel32` (jcc) → mask 4 byte
- `REX + modrm(0x05) + disp32` (RIP-relative) → mask 4 byte
- `REX + B8..BF + imm64` (movabs) → mask 8 byte

Nếu không mask: match rate ~0.9%. Có mask: ~2.5% trên toàn bộ 648k method → **16.292 tên**.
(Mỗi hàm chỉ cần 48 byte đầu; đủ đặc trưng.)

### 6.4 Lọc false positive (bắt buộc)

16.292 match có nhiều cái trùng signature giữa nhiều hàm (hàm nhỏ, prologue giống nhau).

```powershell
python scripts\filter_unique_offsets.py
# -> named_offsets_unique.json : 4.394 match duy nhất
```

Nguyên tắc: với mỗi signature, đếm số function 7.2 có cùng signature; **chỉ giữ khi đếm == 1**.

### 6.5 Kết quả đáng tin (ví dụ 7.2.0)
```
EntityActor::GetPosX                  0x769D330
EntityActor::TickInternal             0x122B4A50
MonoStaminaInfo::set_maxStamina       0x10A8DE50
VCHumanoidMove::JIDHLNCONOE           0x9CB6230
DSCharacterEntity::IsInPreJumpState   0x72DBBE0
LevelTimeManager::remove_OnHourPassed 0x7D120C0
```

### 6.6 Giới hạn
- Hàm nào bị recompile/đổi code → không match.
- Tên trong `dump.cs` bản cũ **cũng có thể đã obfuscate** (vd `JIDHLNCONOE`) → match được tên nhưng
  không hiểu nghĩa. Khi đó phải dùng Phase 7 (runtime counting).
- Tuyệt đối **không** copy offset từ repo khác; nếu có hint thì chỉ dùng để **verify**
  (`verify_candidates.py`), không tin mù.

---

## 7. Phase 5 — Verify RVA trước khi hook

```powershell
python scripts\verify_candidates.py
```

Script in cho từng RVA:
- `func = YES/NO` — có nằm trong `.pdata` không
- 16 byte đầu

**Điều kiện để hook:**
1. `func = YES`
2. byte đầu là prologue: `40 53`, `48 89 5c 24`, `56 57`, `41 57`, `48 83 ec`, `55 41 57`…
3. **KHÔNG** phải `E9 xx xx xx xx` (thunk) — nếu là thunk thì resolve:
   `target = rva + 5 + int32(bytes[1:5])`

Ví dụ thực tế: `Application::set_targetFrameRate` hint `0x146C6C0` chỉ là thunk
→ hàm thật `0x16BA230`.

---

## 8. Phase 6 — Tìm ngữ nghĩa hàm bằng runtime counting

Khi đã có RVA nhưng không biết hàm làm gì:

1. Hook **chỉ đếm** (không sửa return) cho cả class:
   ```cpp
   // pool 128 detour, mỗi detour: gọi original, tăng counter, trả nguyên kết quả
   ```
2. Vào world, làm **đúng 1 hành động** (đánh 1 lần / chạy / nhặt 1 món / dùng E-Q).
3. Counter RVA nào tăng → đó là hàm của hành động đó.
4. Gỡ hook trước khi thử class khác.

Đây là cách duy nhất xác định được semantic khi tên bị obfuscate.

---

## 9. Phase 7 — Hook an toàn (bài học đắt)

### 9.1 Không bao giờ hook lúc load
Gọi `GetTypeInfo` hoặc `MH_CreateHook` từ thread phụ ngay khi DLL load →
**deadlock, game "Not Responding" khi vào world**. Đã gặp thật.

Quy tắc:
- `DllMain`: chỉ `GetModuleHandleA`, mở pipe, spawn thread. **Không chạm game.**
- Inject **sau khi đã vào world**.
- Mọi thao tác game qua lệnh IPC do người dùng bấm.

### 9.2 Mẫu hook MinHook

```cpp
using PresentFn = HRESULT(WINAPI*)(IDXGISwapChain*, UINT, UINT);
static PresentFn g_origPresent = nullptr;

static HRESULT WINAPI det_Present(IDXGISwapChain* sw, UINT sync, UINT flags) {
    /* ... */
    return g_origPresent(sw, sync, flags);
}

MH_Initialize();
MH_CreateHook(reinterpret_cast<void*>(g_base + RVA), det_Present,
              reinterpret_cast<void**>(&g_origPresent));
MH_EnableHook(MH_ALL_HOOKS);   // hoặc enable từng cái
```

### 9.3 Mẫu "chặn damage" (GodMode)
```cpp
// Combat::SetHP(void* combatProp, float newHp, void* method)
using SetHpFn = void(__fastcall*)(void*, float, void*);
static SetHpFn g_origSetHp = nullptr;
static void __fastcall det_SetHp(void* prop, float hp, void* m) {
    if (features().godMode) return;          // bỏ qua set HP -> không nhận damage
    g_origSetHp(prop, hp, m);
}
```

### 9.4 Mẫu "sửa damage" (One Punch)
```cpp
// CalcDamage(a1, a2, AttackResult* res, a4, method)
static void __fastcall det_Calc(void* a1, void* a2, void* res, void* a4, void* m) {
    if (features().onePunch && res)
        *(float*)((uintptr_t)res + 0x14C) *= features().damageMultiplier; // offset 7.2
    g_origCalc(a1, a2, res, a4, m);
}
```

### 9.5 Mẫu gọi thẳng hàm game (không hook)
```cpp
// Time::set_timeScale(float, void* method) @ RVA 0x1448A20
using Fn = void(__fastcall*)(float, void*);
reinterpret_cast<Fn>(g_base + 0x1448A20)(2.0f, nullptr);
```

### 9.6 Quy tắc chống crash
| Sai | Hậu quả |
|---|---|
| Override return của `Tick`/`LateTick`/`Update` | treo game ngay |
| Gọi hàm IL2CPP từ thread phụ lúc load | deadlock |
| Hook hàm thunk `E9` | hook sai chỗ, không bao giờ chạy |
| Gọi `GetTypeInfo` 100k lần đồng bộ trên thread render | giật/treo |
| Đọc pointer không SEH | crash khi gặp null/`0xffffffff` |

Luôn bọc đọc bộ nhớ:
```cpp
static void* readPtrSafe(void* addr) {
    __try { return *(void**)addr; } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
```
**Không đặt `__try` trong hàm có `std::string`/`std::ofstream`** (C2712) → tách hàm helper thuần raw.

---

## 10. Artifact checklist sau khi dump xong

| File | Nội dung |
|---|---|
| `dump_clean.cs` | class + method RVA (không tên) |
| `named_offsets_v2.json` | RVA ↔ tên (16k) |
| `named_offsets_unique.json` | chỉ match duy nhất (4.4k) — **dùng cái này** |
| `FEATURE_OFFSETS.md` | bảng RVA theo chức năng |
| `verify_candidates.py` output | xác nhận hàm thật/thunk |

---

## 11. Bảng lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| `Invalid signature: 0x...` khi decrypt metadata | metadata 4.8+ đổi format | Bỏ hướng decrypt, dùng runtime |
| 0 hit khi scan `AF1BF1FF` / `MHY` | metadata không plaintext trong RAM | Bỏ hướng scan metadata |
| 0 hit khi scan tên method | tên bị mã hoá | Dùng Phase 6 bytecode match |
| GetTypeInfo trả null ở mọi index | chưa vào world / metadata chưa init | Đợi vào world rồi mới scan |
| Hook cài xong nhưng hit = 0 | hook nhầm thunk hoặc nhầm hàm | `verify_candidates.py` lại |
| Game "Not Responding" khi vào world | scan/hook từ thread phụ lúc load | Chỉ thao tác sau khi vào world |
| 66 triệu method RVA rác | dùng `klass+0x30` thay vì `klass+0x100` | Sửa base offset |
| Ghidra `get_xrefs_to` rỗng | chưa auto-analyze | Decompile theo address, hoặc chạy analysis |

---

## 12. Thứ tự thực thi tóm gọn

```
0. Recon           -> version, file sizes, metadata magic
1. Marker scan     -> scripts\scan_offsets_v2.py
2. Ghidra import   -> analyzeHeadless -noanalysis + GUI/MCP
3. Decompile       -> xác định GetTypeInfo (0x527E20) và struct layout
4. Frida validate  -> frida_validate.js, frida_test_apis3.js
5. Dump runtime    -> frida_dump_clean.js  -> dump_clean.cs
6. Tên method      -> build_named_offsets_v2.py -> filter_unique_offsets.py
7. Verify RVA      -> verify_candidates.py
8. Tìm ngữ nghĩa   -> hook class đếm hit khi chơi
9. Hook thật       -> MinHook, sau khi vào world
```
