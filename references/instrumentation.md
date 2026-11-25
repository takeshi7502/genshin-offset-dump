# Instrumentation — what to add before you debug anything

Debugging without these is guesswork that costs days. Each item below exists because its
absence once turned a five-minute fix into a multi-hour investigation.

## 1. First-chance access-violation logger

Engine code swallows a large number of access violations internally. Your own probes can
fault, be caught by a `__except`, and return "no result" — indistinguishable from "the
feature is not implemented". A vectored handler makes the faults visible:

```cpp
static LONG WINAPI FirstChance(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord ||
        info->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    uintptr_t pc    = (uintptr_t)info->ExceptionRecord->ExceptionAddress;
    uintptr_t bad   = info->ExceptionRecord->NumberParameters >= 2
                    ? (uintptr_t)info->ExceptionRecord->ExceptionInformation[1] : 0;
    uintptr_t base  = (uintptr_t)GetModuleHandleW(nullptr);
    LogTrace("AV addr=0x%llX pc=0x%llX rva=0x%llX tid=%lu",
             bad, pc, pc - base, GetCurrentThreadId());
    return EXCEPTION_CONTINUE_SEARCH;   // never swallow: not our handler's job
}
// on attach:  h = AddVectoredExceptionHandler(1, FirstChance);
// on detach:  RemoveVectoredExceptionHandler(h);
```

**Dedupe or you will drown.** A hot path can fault hundreds of times per second. Keep a
small fixed table of `(rva, second, count)` and log the first 2-3 per rva per second, then
a suppressed count.

Rules:

- Return `EXCEPTION_CONTINUE_SEARCH` always. The handler observes; it does not fix.
- Log the **module-relative** RVA, not just the absolute PC — that is what you can look up.
- Log the accessed address: `addr=0xE0` (offset from a null pointer) versus
  `addr=0xFFFFFFFFFFFFFFFF` (a poisoned/stale handle) point at completely different bugs.

## 2. Thread id on every line

```
[12:04:31.881][T15844][TRACE] esp build: enabled=1 inworld=1 entities=110
```

Without the thread id:

- a hang is indistinguishable from a slow loop;
- a wrong-thread call is invisible;
- the difference between "drained on the game thread" and "called from the worker" cannot
  be established after the fact.

## 3. Config-apply logging at an unkillable level

When a command arrives, log **what the receiver parsed**, at `INFO`, not `TRACE`:

```
set_config: god=1 kill=1 noclip=0 esp=0 fps=1 len=95
```

This single line settles three different investigations instantly:

- the command never arrived (`len` missing);
- it arrived but a field name did not match (`god=0` after you sent `true`);
- it arrived and parsed fine, so the bug is downstream.

Do not let a user-facing "verbose logging" toggle disable this line. A `logging=false`
default once turned off the diagnostics needed to diagnose the feature that was broken.

## 4. Session header

At startup, log: build timestamp of your module, host module name and base address,
pointer size, and the game/patch identifier. Two builds of your own DLL are otherwise
indistinguishable in a log, and half of all "the fix didn't work" is a stale binary.

```
===== CORE START 2026-11-25 12:04:03 pid=16344 verbose=1 =====
core module : ...\Core.dll @ 0x7FFE338F0000
host process: ...\Game.exe @ 0x7FF78A1D0000
build: Nov 25 2026 11:58:04
```

## 5. Verdict-style probes, not data dumps

A probe should answer a question. Return booleans per hop plus a human sentence:

```
probe_chain
{"root":"0x...", "world":"0x...", "avatar":"0x...", "entities":187, "in_world":true,
 "x":2560.1,"y":211.4,"z":-1344.3}
-> OK: chain healthy, 187 entities
```

or, for a failure:

```
{"root":"0x0", ...}
-> step 1 failed: not in world, or the root slot moved
```

Include one *independent* live value (player position) so you can tell a stale-but-nonzero
chain from a live one.

## 6. Distinguish "called" from "effective"

Every write should be followed by a read-back in the same code path, logged once per N
calls:

```
dmg: comp=0x... ceil=48 amount=100000 write=0    <- wrote 0 but ceiling says 48: units wrong
dmg: pipeline ok amount=100000                    <- engine path accepted it
```

If you only log the call, you cannot tell "engine refused" from "engine accepted and the
value was meaningless".

## 7. Test-harness hygiene

Your probe harness is code too, and it lies in specific ways:

- **Quoting loss.** Passing structured commands (JSON, embedded quotes) through a shell
  strips quoting silently; the receiver then parses a different string. Write the command
  to a file and have the harness read the file. Two separate "the core ignores my command"
  investigations were this.
- **Stale process id.** Connecting to a pipe named after a dead pid yields a timeout that
  looks like a hung core.
- **Focus dependence.** Screenshotting a window that is not foreground captures whatever is
  on top. Bring the window to top for the capture, then restore; or capture the client
  rectangle directly.
- **Assuming your own write landed.** Screenshot the pixels you expect, and compare against
  a baseline with the feature off.

## 8. Log layout that stays readable

```
<file>: %LOCALAPPDATA%\<tool>\core.log        # in-process, append per session
<file>: <launcher dir>\launcher_trace.log     # host side, mirror of IPC
```

- Append with a session header, never truncate on start (you will want the previous run).
- Flush on every line at `INFO` and above; on `TRACE` every N lines. A hard crash must leave
  the last diagnostics on disk.
- Keep one directory for logs and one naming scheme; do not invent per-feature files.

## 9. Minimum viable instrumentation (copy this list)

- [ ] Vectored first-chance AV logger with per-RVA dedupe, logging RVA + accessed address + tid.
- [ ] Thread id in every line.
- [ ] Session header with module bases and build timestamp.
- [ ] `INFO` line per config apply showing parsed values.
- [ ] One `INFO` line per hook install, and one on first detour hit.
- [ ] Read-back logging on every state write.
- [ ] Verdict-style chain probe.
- [ ] Harness that passes commands via file, not via shell quoting.
