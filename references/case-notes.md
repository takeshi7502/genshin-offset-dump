# Case notes — one real target, as a pattern

These are observations from a single IL2CPP-on-Windows title, kept because the *shape* of
each finding recurs elsewhere. **Do not copy the numbers.** They belong to one patch; the
reasoning is what transfers.

## 1. What the protection removed (and what it did not)

| Standard assumption | Reality on this target | What to do instead |
|---|---|---|
| `GameAssembly.dll` exists | No; IL2CPP code is compiled into the executable (~450 MB, with a second huge executable section) | Read the section table, treat every executable section as code |
| `il2cpp_*` exports available | Hidden since a much older patch | Resolve functions by RVA from static analysis |
| `global-metadata.dat` is parseable | Encrypted (non-standard magic); older dumpers reject it | Do not fight the format; get names from a live process or a cross-version match |
| Method names present as plain strings in memory | Not present | Recover names by normalised bytecode matching against an older build, or by counting hooks |

The general lesson: **inventory what the protection actually removed before choosing an
approach.** Half the failure modes above come from spending a day on a path that was never
open.

## 2. The exception directory can be encrypted

`.pdata` existed with a plausible size, but its contents were random: parsed entries landed
outside every code section. Consequences:

- a naive `rva in pdata_starts` check reports `False` for *everything*, which looks like
  "all my offsets are wrong" when they are fine;
- the correct response is a soft fallback (prologue + boundary) and an explicit "soft"
  verdict, not a mass failure.

Tooling now samples the table and reports "unreadable" before trusting it.

## 3. Structural facts that repeated elsewhere

- **Class layout is shuffled relative to the canonical IL2CPP layout.** Type info pointer at
  `+0x0?`, class at `+0x08`, name at `+0x88`, method entries inline at `klass + 0x100` with
  stride `0x38`. Using the canonical `klass + 0x30` produced tens of millions of garbage
  RVAs — a wrong base offset plus a plausible-looking stride is the most expensive kind of
  error, because the output *looks* like data.
- **`klass + 0x18` is not a method count** (it held typedef indices like 513, 516, 519).
  Verify a presumed count field by checking it correlates with an actual array's length.
- **A "global vars" pointer is not always a pointer.** One slot that a previous build used
  as a root pointer contained garbage on the newer build; features gated on it silently
  never ran. Any chain gate must be verified by observing the value *and* the engine
  agreeing that the world is loaded.

## 4. Where the real bugs actually were

Ranked by time lost, all four were process failures rather than missing knowledge:

1. **Wrong thread.** The damage pipeline faulted every call from a worker thread. The
   pipeline was correct; the caller was not. Fixed by queueing and draining on the frame
   thread — after which the same call reported success.
2. **Stale pointers across threads.** Queueing entity pointers crashed within seconds;
   queueing config ids and re-resolving did not.
3. **Reentrancy.** A detour that resolved a component handle inside itself recursed until
   the client hung. Caching the handle on the worker thread fixed it.
4. **Drawing state assumed, not checked.** A partial engine viewport clipped everything in
   the corners; the assumption "if the draw call returns, pixels appeared" cost hours. A
   large solid-quad probe would have found it in one capture.

## 5. Offsets that were thunks

Several documented "function RVAs" were 5-byte `E9` stubs (frame-rate setter, viewport
getter, and others). Hooking the stub installs a hook nothing calls. Always follow the
chain; record the chain.

One subtlety: not every stub is `E9`. A 7-byte `mov [rip+x], ecx / ret` setter stub also
exists. Treat "the target is shorter than a prologue and ends in `ret`" as a stub too.

## 6. Field-offset semantics that surprised everyone

- An "HP" field that stores a 0..100 ratio, not an absolute value. Writing an absolute
  damage number healed the target.
- A stamina field stored in hundredths; a clamp written in absolute units did nothing.
- A "type" field whose meaning is an enum read across many entities (2 = monster,
  0x1F = avatar, 0x1A = chest, and so on) — the enum values come from the comparison
  constants in the other tool's source, and they make a cheap shape test.
- Chests and oculi had no reliable type code at all: classification had to fall back to the
  display-name string. Not everything is an enum; do not force it.

## 7. What "done" looked like for a single feature

Example, an aura-style damage feature:

1. L1/L2 on both functions (factory + apply), thunk chains recorded.
2. L3 call from the frame thread, no faults, logged.
3. L4: target entity id disappears from the entity list within a few seconds, repeatably,
   with the game still responsive for 30 s afterwards.
4. Nothing in the log from the first-chance handler during the test window.
5. UI status `working`, ledger entry at L4 with the patch name.

Anything short of that is `partial`, and the UI says so.
