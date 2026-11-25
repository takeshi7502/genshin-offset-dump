# Pointer chains — find the root, then walk it

A chain beats a scan. A scan gives you an address that is valid for one session; a chain
gives you a rule that stays valid across sessions and usually across patches (only the
offsets move).

## 1. The shape you are looking for

```
base   = module base (GetModuleHandle of the host)
root   = *(base + ROOT_SLOT)        # a module-level pointer
world  = *(root + OFF_WORLD)        # validated by an engine call, not by bytes
avatar = *(root + OFF_AVATAR)       # +OFF_CFGID = own config id
list   = *(avatar + OFF_LIST)       # +0x18 count, +0x10 array, stride 8, header 0x20
entry  = *(array + 0x20 + i*8)
```

Numbers above are illustrative shapes, not constants. What generalises:

- The root is reachable from a **static data slot**, so it needs no scan.
- One hop is a **self-check**: the engine can tell you whether the root/world is valid.
  Prefer that over reading bytes and hoping.
- The entity container is usually `{array pointer, count}` in some order, with a small
  header so the first entry is not at `+0`.

## 2. Finding the root pointer

Order of attempts, cheapest first:

### 2.1 A slot already known to be the root
From a second artifact (`slot-tables.md`) or from reversing a function that everything
calls first. Verify: the stored pointer must be non-null in game and null/absent before
the world exists.

### 2.2 Enumerate slots, shape-test candidates
Walk the data section for qwords pointing into readable committed memory, and test each
candidate against a shape predicate (below). This is bounded work — tens of thousands of
slots, not gigabytes of heap — and it is repeatable.

### 2.3 Walk backwards from something you can already identify
If you can identify the local player object (e.g. from a position update while you move),
find out where *that* object's address is stored, then continue upwards. A live debugger
with a hardware watchpoint on the pointer field does this in minutes.

### 2.4 Scan — last resort, and never as the only path
If you must scan, scan **committed private memory** for a *run* of pointers that each pass
an entity shape test (readable, type field in range, position accessor returns finite
coordinates). Adopt the best run as a **cache** and keep the re-discovery path in the
product, because the address changes next session.

## 3. Shape tests — cheap predicates that reject fast

A shape test is not proof; its job is to cut a huge candidate set down to a handful
without faulting.

For a **root / world** candidate:
- readable non-null pointer, aligned;
- contains several non-null pointers at plausible offsets (an object graph, not a string);
- survives one engine validation call if one exists (`bool in_world(obj)`).

For an **entity container** candidate:
- `count` in a sane range (1..few thousand) and consistent with the array's readable span;
- every entry pointer readable;
- at least a few entries return finite positions through the engine's position accessor;
- at least one entry whose id resolves *back* through the engine's `by-id` accessor — this
  is the strongest single check, because it proves the id field and the container agree.

For a **type field** candidate at offset `X`:
- values cluster in a small set over many entities (enums do; pointers do not);
- the local player's value is distinct from most monsters' values;
- for the player, `*(entity + X)` is stable while moving and while fighting.

For a **config-id field** candidate at offset `X`:
- values are dense-ish integers, mostly unique among live entities;
- `by_id(entity, *(entity+X)) == entity` returns the same object.

## 4. Verify a field offset by round-trip, not by inspection

Hex dumping and eyeballing "this looks like HP" is the weakest method there is. Use round
trips:

1. Read the field, write a sentinel value, read back. If it reads back, the field is
   writable and you found its position.
2. Then check the *engine* agrees: does the write change observable behaviour?
3. For a signed/derived value (HP, stamina), read it before and after a known action
   (take a hit, sprint). The delta tells you the units, which matters: a value might be
   stored as hundredths, or as a 0..100 ratio rather than an absolute.

Getting units wrong is a classic: writing an absolute damage number into a field that
stores a 0..100 ratio did not damage the target at all — it restored it to full.

## 5. Document the chain as data

Keep the chain in code with one function per hop and one verdict per hop, so a broken
offset produces a *sentence*, not a mystery:

```
base            = 0x...   ok
root            = 0x...   ok
world           = 0x...   ok   [in_world=true]
avatar          = 0x...   ok
local id        = 0x...   ok
local entity    = 0x...   ok
entity list     = 187     ok
-> chain is healthy
```

The probe should also state the *diagnosis*, not just the numbers:

- root empty → not in world yet, or the root slot moved;
- world non-null but `in_world=false` → still loading / transitioning;
- avatar empty → character not loaded, or the avatar offset moved;
- id present but entity empty → the by-id accessor moved;
- list empty → the list holder offset moved, or genuinely nothing nearby.

Also return fine-grained data (player position) in the same probe — it lets you confirm the
chain is live without a second command.

## 6. Re-resolution rules

- Never cache an entity pointer across frames; resolve it fresh when you use it.
- When a pointer must cross a thread, pass the **id** (`thread-and-reentrancy.md`).
- The container's array pointer changes on scene changes; treat a mismatch in
  `(array, count, tag)` as "rebuild the snapshot".
- A chain that fails is not automatically "the game updated". Check game state first: a
  menu, a loading screen and a cutscene all produce null-looking roots.

## 7. Why scanning loses

| | Chain | Scan |
|---|---|---|
| Cost | a few dereferences per use | hundreds of MB scanned, seconds per pass |
| Stability | survives restarts, usually patches | new address every session |
| Failure mode | one hop reads zero (diagnosable) | picks a wrong run that happens to validate (silent) |
| Speed of diagnosis | per-hop verdict | "0 candidates" with no clue which assumption broke |

Scan only to *rediscover* a chain you lost, and then persist what you found as a chain
again.
