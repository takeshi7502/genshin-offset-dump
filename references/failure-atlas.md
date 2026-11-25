# Failure atlas — symptom → cause → the test that separates them

Use this when something does not work and you do not know where to look. Every row is a
failure actually observed at least once; the "test" column is what distinguishes it from
its neighbours.

## A. Feature does nothing

| Test | If it passes, next |
|---|---|
| 1. Log the call site (did the code run at all?) | if never → the toggle is not reaching the core, or the tick is gated |
| 2. Log the thread id at the call | if it is not the game thread → `thread-and-reentrancy.md` Rule 1 |
| 3. Log the arguments and the resolved pointer | if pointer is 0 → the chain/offset is wrong |
| 4. Log the return/read-back after the write | if unchanged → wrong field or wrong object |

| Cause | Evidence |
|---|---|
| Running on a worker thread; engine ignores it | no effect, no fault, call logged on the wrong tid |
| Gated on a hardcoded `in_world = true/false` | feature works everywhere or nowhere, independent of the game state |
| Writes into the wrong field | read-back unchanged, or worse: the opposite effect (see C) |
| Offset from an old patch | `verify` says `L1-FAIL` / `L0-FAIL`, or an AV appears at that RVA |
| Hook on a thunk | hook reports success, hit counter stays 0 |
| Config field name mismatch | receiver log shows the default value, not yours |

## B. Crash / hang at or shortly after inject

| Symptom | Cause | Confirmation |
|---|---|---|
| "Not Responding" within seconds, log stops mid-line | a topmost layered window over a flip-model swap chain blocks `Present` | remove the window; the hang disappears |
| "Not Responding" when enabling one feature | recursion inside a detour | log shows a tight repeated line, or CPU pinned with no new lines |
| Crash on inject, no log at all | work done in `DllMain` (loader lock) | move everything to a spawned thread; keep `DllMain` to `GetModuleHandle` + spawn |
| Crash only in combat | unvalidated pointer used directly | first-chance AV shows a plausible-looking but freed address |
| Crash only when moving between areas | stale entity/array pointer cached across scene change | re-resolve per frame; snapshot rebuild on tag change |

## C. Feature "works" but the opposite happens

The classic: writing a damage number into an HP field **heals** the target to full.

| Observation | Meaning |
|---|---|
| Target survived a huge "damage" but is now at full health | the field is HP (0..100 or absolute), not damage-remaining |
| Value jumps to a maximum after your write | you wrote a large number into a "current/max ratio" style field |
| Everything works for 1 frame then reverts | you wrote to a per-frame snapshot, not the authoritative object |

Rule: after any write, read the field back **and** observe one independent signal
(target disappears, animation changes, value drops over time).

## D. Overlay draws but nothing appears

| Symptom | Cause | Test |
|---|---|---|
| Corner text missing, centre shapes fine | engine's partial viewport clips you | set your own viewport, restore after |
| Flickers or appears every other frame | drew into buffer 0 on a flip model | use `GetCurrentBackBufferIndex()` |
| Textured quad is noise | cropped bitmap but kept the old pitch | repack rows when you change width |
| Nothing at all, all calls succeed | sampler/blend/state create failed silently, or alpha is 0 | check `FAILED()` on every create; force alpha 255 in the shader |
| Visible in windowed, not fullscreen | wrong swap chain / device used for the target | query the device from the swap chain you are drawing into |
| Only half of each quad | rasterizer culling | set `CullMode = NONE` |
| Plate visible only while the mouse moves | you draw in the wrong callback, or on a hidden window's chain | draw from the hooked `Present`/`Present1` only |

Debug order: solid quad → textured quad → label quad → real content
(`in-process-overlay.md` §9).

## E. Values look wrong

| Symptom | Cause |
|---|---|
| Field reads 0 for everything | getter needs a component, you passed the entity (or vice versa) |
| Field reads 0 for the value but writes work | the property is write-only in practice; track it yourself |
| Values look like pointers | wrong struct layout, or you are one dereference short |
| Value is stable but wrong magnitude | units (hundredths, ratio vs absolute, ms vs s) |
| Two different objects give the same values | you are reading a shared/default object, not per-entity |

Units deserve emphasis. A stamina-like field stored as hundredths made a clamp written in
absolute units do nothing visible; reading the raw writes (`val=4240 … 3880 … 3520`) is what
revealed the scale.

## F. Chain / probe problems

| Symptom | Cause |
|---|---|
| Root is null before entering the world, fine after | correct behaviour, not a bug |
| Root non-null but everything under it null | still loading / transitioning; retry after the loading screen |
| Everything looks valid but the list is always empty | list-holder offset moved; the root is right |
| Entity resolved but position is 0,0,0 | position accessor needs the component, or the entity is dormant |
| Probe works on the game thread, times out from your pipe thread | the probe itself calls engine code; run it through the queue |
| Two identical probes return different counts | snapshot rebuild timing; compare `(array,count,tag)` before trusting |

## G. Harness / tooling lies

| Symptom | Cause |
|---|---|
| Command "ignored" by the receiver | shell stripped quotes; write the command to a file |
| Command works when typed, not from a script | same as above |
| Timeout connecting to the pipe | connecting to a pipe named after a dead pid |
| Screenshot is blank / shows the wrong app | window not foreground; raise it for the capture, restore after |
| Log has no new lines after a change | running an old binary — check the build timestamp in the session header |

## H. Escalation: when to stop and re-derive

Stop guessing and re-derive from evidence when any of these is true:

- Two different fixes produced no measurable change.
- You cannot state, for the failing step, which of {not called, called and failed, called and
  ignored} it is.
- You are about to add a special case for "sometimes".

At that point: add the instrumentation from `instrumentation.md` §9 if missing, then walk
the evidence ladder (`SKILL.md` §2) from L0 upward on the one offset the feature depends on.
The bug is almost always at the lowest unverified level.
