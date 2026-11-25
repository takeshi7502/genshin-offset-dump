---
name: genshin-offset-dump
description: General method for discovering, verifying and wiring game offsets — code RVAs and struct field offsets — in a native IL2CPP/Unity target (Genshin and similar), starting from whatever artifacts exist (the target binary, a decompiled second tool, an old dump, a live process). Covers evidence levels L0-L4, slot-table harvesting, pointer-chain reconstruction instead of heap scanning, thread/reentrancy discipline, instrumentation you must add before blaming features, in-process overlay drawing, and a symptom→cause failure atlas. Use when a task is "find the offset for X", "why does this feature do nothing", "port feature Y from tool Z", or "the game crashes / hangs after inject".
---

# Offset discovery — the general method

This is a **process**, not a table of numbers. Numbers rot on every patch; the process
does not. Treat any RVA you read here or anywhere else as a *hint* until it passes the
verification ladder below.

Three rules govern everything else:

1. **Evidence over guesswork.** An offset is only as good as the level it was verified
   at. Never wire a feature to an offset below L3 (see §2).
2. **Synthesise before you scan.** Most games still hold the root pointer you need in a
   static data slot. Enumerating slots beats scanning the heap, every time.
3. **Instrument before you blame.** If you cannot see a function being called, a config
   being applied, or a memory access faulting, you are guessing. Add the instrumentation
   first (§8).

---

## 1. Vocabulary that keeps you honest

Confusing these five is the most common cause of "it doesn't work".

| Term | Meaning | Verified by |
|---|---|---|
| **Code RVA** | Address of a function, relative to the module base | L1+L2 (`.pdata`, thunk follow, prologue) |
| **Field offset** | Byte offset inside an object, e.g. `entity+0x3D4 = config id` | shape test + read-back (§6) |
| **Slot** | A static data qword that *stores* a code RVA or an object pointer | dereference + section check |
| **Thunk** | A 5-byte `E9 rel32` stub that jumps to the real body | thunk follow; hook the target, not the stub |
| **Chain** | A fixed sequence of dereferences from a static address to the object you need | one verdict per hop (§6) |

Two more that matter in practice:

- **Root pointer** — the module-level pointer everything hangs off (the `GlobalVars`
  analogue). Find it once and most other offsets become trivial.
- **Shape test** — a cheap predicate that a candidate pointer *looks like* the object you
  want (readable, dense pointer array, a count field in range, an id that resolves back
  through a known accessor). Shape tests are how you avoid scanning for a needle.

---

## 2. The evidence ladder

Every offset climbs these levels *in order*. A level is a gate, not a memo.

| Level | Claim | How to test | Failure looks like |
|---|---|---|---|
| **L0** | The address is inside a mapped section of *this* build | PE/ELF section table: is the RVA in a code/data section? | RVA from an old patch lands in padding or another section |
| **L1** | It is a real function entry, not mid-instruction | Exception directory (`.pdata` on x64) or symbol table contains it; when that table is encrypted, fall back to prologue+boundary and treat the result as *soft* | Caught a mid-function RVA: `0x1F9E20` "worked" as a viewport getter and faulted; the real entry was `0x1A2522D0`, a thunk to `0x146A280` |
| **L2** | It is not a thunk; prologue sane; argument shape known | Follow `E9 rel32` to the final target; read the first instructions and every call site in the disassembly to see what each parameter dereferences | Hooking `set_targetFrameRate` at `0x146C6C0` (a `E9` stub) installs a hook that never runs |
| **L3** | It can be called from the right thread with the right arguments without faulting | Call it from a controlled probe and check for faults + plausible return | Fault every time: wrong thread, or the first argument must be a class/static pointer, not an RVA |
| **L4** | It produces the intended observable effect in game | Measure state before/after, not the return value | "Returned OK" but the monster still has full HP: you wrote *damage* into an *HP* field and healed it |

Practical consequence: keep a ledger (`scripts/offset_ledger.py`). If an entry sits at L2
and nobody tested it, mark the feature `partial` in the UI instead of claiming it works.

---

## 3. Phase A — inventory before you touch anything

Collect and *record* these. Missing any one of them costs hours later.

- [ ] **Target binary** — exact file, its size, version string, image base, section table.
- [ ] **Second artifact with labels** — an older build's dump, a decompiled copy of a
      different tool for the same game, a public symbol file, a `.i64`/Ghidra project.
      This is usually the single highest-value input (§5).
- [ ] **Decompiled sources** — even a mid-quality Ghidra dump of *another* implementation
      gives you argument shapes and call sites you cannot get from a stripped binary.
- [ ] **A live process** you may attach to, and a known-good state (in game, in world).
- [ ] **An existing config/schema** — the field names a tool already uses tell you which
      features exist and what the code expects (useful as a checklist, never as truth).
- [ ] **How you will observe** — a log file you control, a probe command, a read-back.

Write the inventory into the repo (a `docs/` file), not into chat.

---

## 4. Phase B — build the RVA map

Do B2 first. It is by far the cheapest.

### B1. Static, from the target binary
`scripts/pe_tool.py sections <pe>` then `scripts/pe_tool.py verify <pe> spec.txt`.
Marker-string scanning and bytecode matching (see `references/static-analysis.md`) give
*candidates*; they do not prove the function does what its name suggests.

### B2. Harvest a slot table from a labelled artifact  ← highest ROI
Tools routinely store every game function pointer in static data slots and call them
through that slot. If you have a decompiled copy of any such tool:

1. Locate the slot region in **its** binary (dense qwords whose values are code RVAs).
2. Dump `slot -> stored RVA`.
3. For each slot, find which decompiled function reads it — that names the RVA by
   *behaviour*, not by guesswork.
4. Verify every harvested RVA against **your** target binary (B1). RVAs move; slot shapes
   do not.

`scripts/pe_tool.py slotmap <bin> <start> <end> --src <decompiled-dir>` does all four.
Worked example and the reasoning: `references/slot-tables.md`.

### B3. Cross-version matching
When names are encrypted but you hold an old dump with names, match normalised prologue
bytes (mask rel32/disp32/imm64 before comparing, then keep only signatures that are
unique). See `references/static-analysis.md` §4.

### B4. Decide, don't accumulate
Produce a short candidate list per feature with a *reason* for each. Ten reasoned
candidates beat two hundred scanned addresses.

---

## 5. Phase C — reconstruct the chain, don't scan the heap

Heap scanning is a last resort and it is unreliable: the array address changes every
session, and a stale pointer is a crash. Prefer this order:

1. **Enumerate static slots.** Walk the data section for qwords that point into readable
   memory; shape-test each candidate.
2. **Fetch the game's own view of the world.** Most engines expose a root object reachable
   from a module-level pointer. Verify it by asking the engine to validate it (a
   `bool in_world(root)` style call) rather than by inspecting bytes.
3. **Walk from an object you can already identify.** Local player → component list →
   entity list is a common and stable shape.
4. **Only then** scan memory, and when you do, adopt the result as a *cache with a
   re-discovery path*, never as the single source of truth.

Document the chain as a first-class artifact — one line per hop, each with its own
verdict:

```
base                = module base
root                = *(base + SLOT)              # root pointer, must be non-null
world               = *(root + OFF_WORLD)         # validated by engine call
avatar              = *(root + OFF_AVATAR)        # +OFF_CFGID = own id
list                = *(avatar + OFF_LIST)        # +0x18 count, +0x10 array
entry(i)            = *(array + HEADER + i*8)
```

Details, shape tests and the "one verdict per hop" probe format:
`references/pointer-chains.md`.

---

## 6. Phase D — runtime verification

Design probes so one command answers one question, and make the answer *machine
readable*. A good probe returns, per hop: the value, and a boolean for "this hop is
healthy". Then a broken offset is obvious from the verdict line instead of requiring a
debug session.

Rules:

- **Read back after every write.** Write position → read position. Write HP → read HP.
  If the read-back is unchanged, the write went somewhere harmless and the "feature"
  is a no-op, not a bug in the UI.
- **Prefer the engine's own action.** If the engine has `Pickup(mgr, id)`, call it. Do not
  emulate it by mutating fields — you will desynchronise a state machine.
- **Never mutate timing/tick fields of a stateful object to "skip" something.** Zeroing a
  dialogue object's timing fields parked its state machine at the last line forever.
  Send the same input the player would send instead.
- **Distrust any single observation.** Take a baseline, act, re-measure.

---

## 7. Phase E — call discipline (the four rules)

These four rules account for nearly every "it does nothing" and nearly every hang.

### Rule 1 — engine calls belong to the engine's thread
IL2CPP and most engine APIs are not thread-safe. A worker thread that calls
object-allocating APIs will occasionally fault, deadlock, or silently do nothing.

Pattern: the worker **enqueues** intent; a per-frame callback that already runs on the
game thread **drains** the queue. Any per-frame callback works (`Present`, an input
dispatch, a tick detour) — pick one that always runs on that thread, and never drain from
a UI-thread callback.

### Rule 2 — a detour must never re-enter itself
Resolve and cache anything the detour needs on another thread *before* the detour runs.
If you must call game code from inside a detour, guard it (`thread_local` or an atomic
exchange) — one hook that resolved a component handle inside its own detour recursed
until the client hung.

### Rule 3 — queue identities, not pointers
An entity pointer observed on the worker thread may be freed before the game thread uses
it. Queue the stable id (config id / instance id) and re-resolve on the consuming thread.

### Rule 4 — arguments are found, not assumed
Given `f(a, b, c)`, the same signature can mean `(entity)`, `(component)`,
`(staticObject)`, `(classPointer)` or `(configId)`. Resolve by:
1. Reading the disassembly for what `a` dereferences (`[rcx+0x20]` implies an object).
2. Reading every call site in the decompiled reference tool.
3. Testing both candidate shapes in one instrumented run and comparing the log.

A real example where all three mattered: the damage-result factory took a **class
pointer read from a global**, not an RVA and not a static address — every other shape
faulted.

Reference: `references/thread-and-reentrancy.md`.

---

## 8. Phase F — instrumentation you add *first*

Add these before debugging any feature. Without them you cannot tell "not called" from
"called and failed" from "called and ignored".

1. **First-chance access-violation logger** — a vectored handler that records the faulting
   RVA, the accessed address and the thread id, deduped per RVA per second. Engine code
   swallows many faults; without this, a "silent" feature looks like a logic bug.
2. **Per-line thread id in the log** — a hang and a wrong-thread call look identical
   without it.
3. **A log line for every config apply, at a level your config cannot disable.** A
   `logging=false` default once turned off the very traces needed to diagnose it.
4. **Session header** with build timestamp, module bases, and the patch under test.
5. **Harness hygiene:** when a test harness passes structured arguments through a shell,
   quoting is lost silently. Write the command to a file and read it; then log what the
   receiver actually parsed. Two "the core ignores my command" investigations were
   PowerShell eating quotes.

Reference: `references/instrumentation.md`.

---

## 9. Phase G — drawing in-process (only if the task needs an overlay)

A separate topmost layered window over a flip-model swap chain can make the game's
`Present` block and the client stop pumping messages. Draw **into the game's frame**
instead, from the `Present`/`Present1` hook:

- Query `IDXGISwapChain3::GetCurrentBackBufferIndex()` — buffer 0 is not always current.
- **Set your own viewport** and restore the previous one. The engine may leave a partial
  viewport bound, which clips anything in a corner and makes you think your draw failed.
- When cropping a bitmap, **repack rows** — the pitch you upload must match the width you
  claim, or the texture is garbage.
- Set the alpha channel explicitly; GDI leaves it at zero, so a fully opaque plate blends
  to invisible.
- Keep one texture atlas for all text and draw per-item quads from it.

Full checklist with the failure each item prevents: `references/in-process-overlay.md`.

---

## 10. Wiring order per feature

Never jump from "found an RVA" to "user-visible toggle". Go in this order, and stop at
the first step that fails — that is where the bug is.

1. **Read** the value the feature needs, and log it while the player does the thing.
2. **Verify the read** matches reality (position moves, id is stable, count is plausible).
3. **Write once**, then read back and log both.
4. **Verify the effect** with an independent observation (entity disappears, HP decreases,
   camera FOV changes) — not the function's return value.
5. Only then expose the toggle, with the UI status reflecting the *highest level reached*
   (`working` = L4 observed, `partial` = L2/L3, `unavailable` = no path).

If a feature is `partial`, say so in the UI. An honest `partial` costs nothing; a false
`working` costs the reporter an afternoon.

---

## 11. Failure atlas — symptom, cause, test

| Symptom | Most likely cause | Test that distinguishes it |
|---|---|---|
| Hook installs, hit count 0 | Hooked a thunk, or the wrong function | `pe_tool.py thunk` + verify the target is called in the disassembly |
| Feature does nothing, no errors | Called from a worker thread; engine ignores it | Log the thread id at the call site; compare to a known per-frame callback |
| Feature does nothing but the log says OK | Wrote to the wrong field (e.g. damage into HP) | Read back the field before/after |
| All engine calls after some action start failing | Fault inside a queue item left state broken | First-chance AV logger, look at the last RVA before the failures |
| Client hangs ("Not Responding") after inject | Recursion inside a detour, or a blocking call on the UI thread | Look for game calls inside detours; check for a layered topmost window |
| Overlay draws (per logs) but nothing appears | Partial viewport, wrong buffer index, pitch mismatch, or zero alpha | Draw a large solid quad first: if it shows, the textured path is at fault |
| Values look like garbage after a read | Wrong struct layout assumption | Dump the object's first 0x100 bytes and look for a plausible shape |
| Works once, breaks after the target dies | Queued a pointer instead of an id | Re-resolve from id on the consuming thread |
| Config never reaches the core | Harness quoting / wrong field name | Log the parsed values inside the receiver |
| Random crashes only in combat | Unvalidated handle used directly | Validate handle by reading one field through SEH first |

More, with the reasoning behind each: `references/failure-atlas.md`.

---

## 12. Definition of done

A feature is done when all of these are true, and the report says which are not:

- Every offset it uses is in the ledger at the level claimed, with the patch it was tested on.
- The effect was observed independently, at least once, and the observation is reproducible.
- The failure mode when the target is absent (not in world, entity gone, no avatar) is a
  clean no-op, not a crash.
- The UI status matches reality.
- The log contains enough to diagnose it next time (thread, verdict, values).

Report format: what changed · evidence level reached · what was actually run · what is
unverified and why.

---

## 13. Quickstart — the whole loop for one feature

Copy, adapt paths, and do not skip the gates.

```bash
S=scripts                      # this skill's scripts directory
PE=<target binary>

# 1. shape of the target
python $S/pe_tool.py sections $PE

# 2. candidate RVAs: harvest from any labelled artifact, then verify on THIS build
python $S/pe_tool.py slotmap <labelled-binary> 0x1F8000 0x1FAA00 \
        --src <decompiled-dir> --json slots.json
#    write the ones you care about into spec.txt as  name=0xRVA  and:
python $S/pe_tool.py verify $PE spec.txt --json verify.json
#    -> OK / THUNK(use the suggested address) / SOFT-OK / FAIL. Obey it.

# 3. record what you now believe, and at which level
python $S/offset_ledger.py set ledger.json --name FeatureFn --rva 0x123456 \
        --kind code --level L2 --source "slot 0x... + verify" --patch <patch>

# 4. read the argument shape, do not guess it
python $S/pe_tool.py disasm $PE 0x123456 --len 96

# 5. chain, not scan (when the feature needs an object)
#    implement probe_chain: one verdict per hop, plus one live value

# 6. wire it: engine calls on the game thread, ids not pointers, no engine calls in detours

# 7. prove the effect, then raise the level
python $S/offset_ledger.py bump ledger.json --name FeatureFn --level L4 \
        --note "target entity removed within 3 s, game responsive 30 s"
```

If step 2 returns `SOFT-OK`, remember that it is a heuristic verdict: it must pass an L3
call test before it may be wired to anything.

## 14. Adapting to a different target

The method is not tied to one game or one engine.

| Target | What changes | What stays |
|---|---|---|
| Another IL2CPP/Unity title | Metadata layout, class stride, slot names | Section table → candidates → verify → chain → thread discipline |
| A title with symbols or a public SDK | Start at L2 with the symbol; skip name recovery | Evidence levels, chain verification, read-back |
| A non-Unity native game | No IL2CPP plumbing at all; more work on struct layout | Slot harvesting, thunk follow, probes, instrumentation, failure atlas |
| Console / emulator targets | Address translation differs (no PE) | Everything conceptual: ladder, round-trip writes, thread rules |

The two things that never transfer by copying are **offsets** and **struct layouts**. The
two things that always transfer are the **ladder** and the **diagnostic discipline**.

---

## References

| File | Read it when |
|---|---|
| `references/static-analysis.md` | Building candidates from a binary; marker scan, `.pdata`, thunk follow, cross-version bytecode matching |
| `references/slot-tables.md` | You have any second artifact with labels and want a labelled RVA map fast |
| `references/pointer-chains.md` | You need the entity/player/world chain, or a root pointer, or you are tempted to scan the heap |
| `references/thread-and-reentrancy.md` | Before writing any hook or any engine call |
| `references/instrumentation.md` | Before debugging your first failing feature |
| `references/in-process-overlay.md` | The task needs ESP/FPS/menu drawn over the game |
| `references/failure-atlas.md` | Something does not work and you do not know where to look |
| `references/hook-dll-skeleton.md` | You need a working host-DLL + IPC shape to hang everything off |
| `references/case-notes.md` | You want one worked example — what the protection removed, and which bugs were process failures |

## Scripts

| Script | Purpose |
|---|---|
| `pe_tool.py` | `sections`, `verify` (L0/L1/L2 verdicts), `thunk`, `disasm`, `slotmap` |
| `offset_ledger.py` | Durable record of every offset with its evidence level and patch |
| `scan_offsets_v2.py`, `scan_offsets_static.py` | Marker-string scans for IL2CPP plumbing candidates |
| `verify_candidates.py` | Legacy per-RVA prologue check (superseded by `pe_tool.py verify`) |
| `build_named_offsets_v2.py`, `filter_unique_offsets.py`, `export_ida_bytes.py` | Cross-version bytecode matching to recover names |
| `run_frida.py`, `frida_*.js` | Runtime validation, struct layout, controlled dumps |
| `find_xrefs.py`, `map_method_names2.py` | Locating cross-references in a dump |

All scripts are read-only against the target. They never patch a file and never require
the game to be running except the Frida ones.
