# Thread discipline and reentrancy

Every hard hang and most "the feature does nothing" reports come from this file. Read it
before writing a single hook.

## 1. Rule 1 — engine calls belong to the engine's thread

IL2CPP object allocation and most engine setters are not thread-safe. Calling them from an
arbitrary worker thread gives one of three outcomes, in decreasing order of kindness:

1. an access violation (**good** — you see it in the log and fix it);
2. a silent no-op (**bad** — the feature looks implemented and does nothing);
3. a deadlock or corrupted heap (**worst** — the client freezes with no stack of yours).

### The queue pattern

```
worker thread                     game thread (per-frame callback)
------------                      --------------------------------
mu.lock()                         drain():
q.push(intent)                      pop one intent
mu.unlock()                         resolve ids -> pointers
                                    call engine
                                    log result
```

Implementation notes that matter:

- **Pick a drain site that always runs on the game thread.** Any per-frame callback works
  (a `Present` hook, an input-dispatch detour, a tick detour). Do not drain from a
  UI-thread callback: that is a different thread with the same problem.
- **Bound the queue** (drop oldest) so a stuck consumer cannot grow memory forever.
- **One consumer.** Use an atomic "draining" flag so two callbacks cannot run the engine
  path concurrently.
- **Queue identities, not pointers** (Rule 3 below).

```cpp
// queue side
void PushDamage(uint32_t configId, float amount) {
    std::lock_guard<std::mutex> lk(mu);
    if (q.size() > 64) q.pop_front();
    q.push_back({configId, amount, /*instant*/ amount <= 0.f});
}

// consumer side, called from the game thread only
void Drain() {
    if (InterlockedCompareExchange(&draining, 1, 0) != 0) return;
    for (;;) {
        Job j; bool have = false;
        { std::lock_guard<std::mutex> lk(mu);
          if (!q.empty()) { j = q.front(); q.pop_front(); have = true; } }
        if (!have) break;
        uintptr_t ent = ResolveById(j.configId);   // re-resolve HERE
        if (ent) Apply(ent, j.amount);
    }
    InterlockedExchange(&draining, 0);
}
```

## 2. Rule 2 — a detour must never re-enter itself

If a detour resolves anything through game code, and that resolution can reach the same
function you hooked, you get unbounded recursion. Symptom: the client stops responding
within milliseconds of enabling the feature, and the log shows thousands of identical
lines or none at all.

Two fixes, use both:

**Cache on another thread.** The detour may only *compare* against precomputed values:

```cpp
// worker thread, every tick
g_localHandle = god_mode ? ResolveCombatHandle(LocalEntity()) : 0;

// detour, game thread — no engine calls at all
void __fastcall DetourSetHp(void* comp, float hp) {
    if (t_inDetour) { orig(comp, hp); return; }      // guard
    UpdateCeiling(comp, hp);
    if (god_mode && comp == g_localHandle && hp < ceiling) return;
    t_inDetour = true; orig(comp, hp); t_inDetour = false;
}
```

**Guard with `thread_local` or an atomic.** Cheap and catches the accidental case.

Both defects are worth naming because they look different and have the same cause:

- a hook that resolved the local component inside its own detour recursed until the hang;
- a hook that only compared a cached pointer was safe.

## 3. Rule 3 — queue identities, not pointers

A pointer observed on the worker thread can be freed between queueing and use. Objects die
constantly: local loot is picked up, monsters are killed, scenes reload.

- Queue the **stable id** (config id / instance id / spawn index).
- Re-resolve on the consuming thread with the engine's own `by-id` accessor.
- Validate the resolved object one more time (read one field through SEH) before writing.

A kill-aura implementation that queued pointers crashed instantly; the same code queueing
ids and re-resolving never did.

## 4. Rule 4 — arguments are found, not assumed

`f(a, b)` can mean any of these and the definition is not in the name:

| Shape | Tells |
|---|---|
| object | dereferenced at a fixed offset (`[rcx+0x20]`) |
| component | passed to a getter that returns a different pointer |
| class pointer | passed to a class-lookup helper, or itself dereferenced twice to reach a name |
| integer id | compared, or used as a table index |
| RVA / static address | added to the module base by the caller |
| out-parameter | written to, then returned unchanged |

Resolution procedure:

1. **Read the disassembly** of the function (`pe_tool.py disasm`). The first 30 bytes
   usually settle it.
2. **Read every call site** in your labelled artifact. The call site is the evidence; the
   callee is the inference.
3. **Test both candidate shapes in one instrumented run.** Log the fault per shape. Do not
   run one shape per session and guess from the result.

A worked case where all three were needed: a damage-result factory took a pointer that the
game itself loaded from a `rip`-relative global. Passing the RVA faulted, passing a static
address faulted, passing the *value of the global* worked. The disassembly showed the same
`mov rcx, [rip+X]` load the game performs, which is what identified it.

## 5. Rule 5 — never fake engine state to "skip" something

A dialogue-skip implementation zeroed the timing fields of the dialogue object. The
typewriter finished, and then the state machine had nothing to advance on: the dialogue
never closed and the player was stuck in it.

Prefer, in this order:

1. the engine's own public action (send the same key/message the player would);
2. a documented setter;
3. a direct field write — and if you must, restrict it to fields whose meaning you have
   round-trip verified, and never to fields that drive a state machine.

## 6. Checklist before enabling any hook

- [ ] Target verified L1/L2 on **this** build, not a thunk.
- [ ] Detour body contains **no** engine calls that could reach itself; anything needed is
      cached on the worker thread.
- [ ] Reentrancy guard present.
- [ ] Arguments verified by disassembly **and** a call site.
- [ ] A disable path exists (unhook / stop queueing) and is reachable from the UI.
- [ ] Log line on install, and one on first detour hit.
- [ ] The feature still degrades to a no-op when its preconditions are missing (not in
      world, entity null, handle invalid).
