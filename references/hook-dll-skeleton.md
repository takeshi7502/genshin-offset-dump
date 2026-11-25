# Host DLL skeleton — inert load, IPC-driven work

This is the shape that keeps a modded client alive: the DLL touches nothing at load time and
every engine operation happens later, on request, from the right thread. It is an *example*
of the constraints in `SKILL.md` §7, not a requirement to copy verbatim.

## 1. Lifecycle rules

```
DllMain        -> GetModuleHandle (module base) + spawn thread + return
                  NEVER: engine calls, symbol resolution, hooking, scanning, allocation
worker thread  -> open IPC pipe, serve commands, run per-tick bookkeeping
game thread    -> every engine call, drained from a per-frame callback
```

Why: `DllMain` runs under the loader lock. Doing anything that waits for another thread, or
that triggers the CRT/loader (static init, `std::thread` join, `LoadLibrary`) deadlocks. The
visible result is a client that freezes during startup or on the first area load.

## 2. Minimal `DllMain`

```cpp
static HMODULE g_self = nullptr;
static uintptr_t g_base = 0;
static volatile bool g_running = true;

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = h;
        g_base = (uintptr_t)GetModuleHandleW(nullptr);   // host image
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_running = false;
    }
    return TRUE;
}
```

`g_base` via `GetModuleHandleW(nullptr)` — never a hardcoded base, never assume the module
name matches something you saw in a dump.

## 3. Worker loop shape

```
WorkerThread:
    diag::Init(true)                  # log file, session header, module bases
    ResolveAnchors()                  # optional: verify/repair RVAs at startup
    StartPipeServer()                 # commands arrive here
    loop while running:
        refresh state connected to the chain (cheap, read-only)
        run feature ticks that ONLY enqueue
        sleep ~8 ms
    stop pipe, remove hooks, close log
```

Nothing in this loop may call engine code directly. Ticks that need the engine enqueue an
intent (`thread-and-reentrancy.md` §1).

## 4. Safe memory access

```cpp
static bool ReadMem(uintptr_t addr, void* out, size_t n) {
    if (!addr || !out || !n) return false;
    __try { memcpy(out, (const void*)addr, n); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}
template <typename T> bool ReadVal(uintptr_t a, T& v) { return ReadMem(a, &v, sizeof(T)); }
```

Rules:

- `__try` must not appear in a function that has objects needing unwinding (`std::string`,
  `std::ofstream`, `std::thread`) — MSVC error C2712. Put the SEH in a small raw helper and
  call it from the larger function.
- Every hop of every chain goes through this. One unguarded dereference is a crash on a
  null or a poisoned pointer (`0xFFFFFFFFFFFFFFFF`).
- Validate a handle by reading one field through this before trusting it, even if a function
  just returned it.

## 5. Hook engine expectations

Whatever inline-hook implementation you use, it must:

- decode instruction boundaries to relocate a prologue (minimum ~14 bytes for a 64-bit
  absolute jump), not just copy 5 bytes;
- refuse to hook a `E9` thunk without following it (or follow it for you);
- relocate RIP-relative operands when the trampoline is beyond ±2 GB;
- fail loudly (`installed`, `failed`, reason) and be logged.

A self-test that hooks two local functions, checks both directions (detour sees the call,
trampoline returns the original result) and removes them cleanly, catches most engine bugs
before the game does. Keep it in CI/build.

## 6. Pipe protocol

Keep it line-delimited JSON with one reply per request. Minimum surface for offset work:

| Command | Purpose |
|---|---|
| `probe_chain` | verdict per hop of the pointer chain |
| `get_state` | counters, hook count, in-world, tick time |
| `set_config {...}` | feature configuration; must log what it parsed |
| `set_entity_array` / `set_local_entity` | manual override from the offset page |
| `read_ptr` / `mem_dump` | inspect one address (bounded size) |
| `field_probe` | shape-test candidate field offsets |
| `scan_arrays` (optional) | rediscovery path when the chain is lost |

Implementation notes:

- One reader thread, serialised handlers. Never call engine code from the pipe thread —
  enqueue instead, then wait for the result with a short timeout and return it.
- Replies must be single-line JSON so a client can read by line.
- Log every command at `INFO` with its parsed effect (`instrumentation.md` §3).

## 7. Config bus

Two options, both fine:

- **Push**: the host serialises config into one JSON line and sends it on change.
- **Pull**: the host writes a config file and sends `reload`; the core reads the file.

Prefer push for latency and pull as a fallback when the pipe is not up yet. Either way, log
the parsed values — never log only "config applied".

## 8. Shutdown

```
on detach: stop queueing -> unhook all -> stop pipe -> close log
```

Order matters: unhook before tearing down state the detours read, otherwise a detour runs
once against freed memory. If a clean shutdown is impossible (host process is exiting), do
nothing in `DLL_PROCESS_DETACH` except set the flag — the process is going away anyway.

## 9. Pre-flight checklist

- [ ] `DllMain` contains no engine work, no static objects requiring init, no waits.
- [ ] All chain reads go through SEH-guarded helpers.
- [ ] Every engine call happens on the game thread, via the queue.
- [ ] Detours are reentrancy-guarded and contain no engine calls.
- [ ] Hook engine self-test passes.
- [ ] Every command is logged with its parsed effect.
- [ ] A disable path exists for every hook and every queue.
- [ ] Log file flushes `INFO` lines so a hard crash leaves evidence.
