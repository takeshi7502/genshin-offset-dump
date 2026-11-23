# Skeleton DLL an toàn cho Genshin (headless, IPC-driven)

Mẫu này là bản đã chạy ổn định: **load xong không đụng gì vào game**, mọi thao tác qua IPC.
Đây là cách duy nhất tránh "Not Responding" khi vào world.

## 1. Nguyên tắc

```
DllMain  -> chỉ GetModuleHandleA + LogLine + spawn thread IPC
        -> TUYỆT ĐỐI không: GetTypeInfo, MH_*, scan, hook
IPC cmd  -> mới được: scan / install hook / remove hook
Hook     -> chỉ cài khi game đã vào world
```

## 2. DllMain tối thiểu

```cpp
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        gi_tool::paths::setModuleHandle(h);
        DisableThreadLibraryCalls(h);
        g_base = (uintptr_t)GetModuleHandleA("GenshinImpact.exe");  // chỉ lấy base
        LogLine("[dll] inert load base=0x%llX", (unsigned long long)g_base);
        std::thread(ipcThread).detach();
    }
    return TRUE;
}
```

## 3. Đọc bộ nhớ an toàn

```cpp
static void* readPtrSafe(void* addr) {
    __try { return *(void**)addr; } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
static const char* safeCstr(void* p) {
    if (!p) return "";
    __try {
        const char* s = *(const char**)p;
        if (!s) return "";
        volatile char c = *s; (void)c;              // force fault here
        return (strlen(s) < 200) ? s : "";
    } __except (EXCEPTION_EXECUTE_HANDLER) { return ""; }
}
```

`__try` **không** đặt trong hàm có `std::string`/`std::ofstream` (lỗi C2712).
Tách thành helper thuần raw rồi gọi từ hàm có object.

## 4. Pool hook generic (chỉ đếm)

Cần N detour tĩnh vì MinHook yêu cầu con trỏ hàm cố định:

```cpp
struct DynHook { uintptr_t rva = 0; void* orig = nullptr; std::atomic<int> hits{0}; };
static std::vector<DynHook*> g_dynHooks;

// sinh 128 hàm tường minh (đừng dùng macro token-paste với biểu thức)
#define DET(i) \
static uintptr_t __fastcall dynDet##i() { \
    auto* h = (i < (int)g_dynHooks.size()) ? g_dynHooks[i] : nullptr; \
    using F = uintptr_t(__fastcall*)(); \
    uintptr_t r = (h && h->orig) ? reinterpret_cast<F>(h->orig)() : 0; \
    if (h) h->hits++; \
    return r; }
```

Gọi original **không tham số** vẫn an toàn trên x64: các thanh ghi tham số (RCX/RDX/R8/R9/XMM)
không bị detour chạm tới.

## 5. Cài / gỡ hook

```cpp
static bool hookOne(uintptr_t rva) {
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) return false;
    void* target = (void*)(g_base + rva);
    auto* h = new DynHook(); h->rva = rva;
    int idx = (int)g_dynHooks.size();
    if (MH_CreateHook(target, g_dynDet[idx], &h->orig) != MH_OK) { delete h; return false; }
    if (MH_EnableHook(target) != MH_OK) { MH_RemoveHook(target); delete h; return false; }
    g_dynHooks.push_back(h);
    return true;
}
```

## 6. IPC protocol (named pipe, message mode)

Pipe: `\\.\pipe\GITool_IPC`

| Lệnh | Trả lời | Tác dụng |
|---|---|---|
| `PING` | `OK` | test |
| `STATE` | chuỗi `k=v;...` | telemetry |
| `CLASSES` | `OK:SCANNING ...` | bắt đầu quét async |
| `GETCLASSES` | `OK;Name1;Name2;...` | lấy kết quả |
| `METHODS <Class>` | `OK;0:0xRVA;1:0xRVA;...` | liệt kê method |
| `HOOK_RVA 0x...` | `OK` / `ERR:*` | hook 1 method (chỉ đếm) |
| `HOOK_CLASS <Class>` | `OK:HOOKED_CLASS ok=N` | hook cả class |
| `UNHOOK_ALL` | `OK:ALL_REMOVED` | gỡ hết |
| `HOOKSTATS` | `OK;0xRVA=hits;...` | counter |
| `RELOAD_CONFIG` | `OK:RELOAD_QUEUED` | đọc lại config file |

Server loop: `CreateNamedPipeW` → `ConnectNamedPipe` → `ReadFile` → dispatch → `WriteFile` →
`FlushFileBuffers` → `DisconnectNamedPipe` → `CloseHandle` → lặp.

## 7. Config bus

`artifacts/local_config.txt`, format `key=value` mỗi dòng.
Launcher ghi file rồi gửi `RELOAD_CONFIG`; DLL đọc lại. Không cần JSON.

## 8. Checklist trước khi bật bất kỳ hook nào

- [ ] Game đã ở **menu chính hoặc trong world**
- [ ] `verify_candidates.py` báo `func = YES`
- [ ] byte đầu không phải `E9` thunk
- [ ] hook chỉ **đếm** trước, xem hit > 0 rồi mới sửa logic
- [ ] có `UNHOOK_ALL` để thoát nhanh nếu game lag
