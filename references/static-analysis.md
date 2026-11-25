# Static analysis — from a stripped binary to a candidate list

Everything here is read-only and works without running the game. Output is a *candidate
list*, never a verdict; see `SKILL.md` §2 for the gates.

## 1. Know the target's shape first

```bash
python scripts/pe_tool.py sections <binary>
```

What you are looking for:

- **Image base** — every "RVA" in a dump is `VA - image_base`. Confirm it, never assume.
- **Code sections** — usually more than one (`.text` plus, on IL2CPP-in-exe builds, a
  second large executable section). A code pointer outside every executable section is
  garbage.
- **`.pdata`** — the exception directory. On x64 this is the only trustworthy source of
  function starts when the binary has no symbols.
- **Data section** — where the slot tables live (§`slot-tables.md`).

## 2. Function starts from `.pdata`

```python
# RUNTIME_FUNCTION is 12 bytes: BeginAddress, EndAddress, UnwindInfo (u32 RVAs)
for i in range(0, len(pdata) - 11, 12):
    begin = struct.unpack_from("<I", pdata, i)[0]
```

Why not heuristic: scanning backwards from an address to the previous `0xCC` padding
returns **mid-function** addresses on optimised builds. Every mid-function "offset" you
hook either crashes immediately or silently corrupts a prologue. `pe_tool.py verify`
already flags these as `L1-FAIL mid-function`.

A real cost of getting this wrong: a "viewport getter" RVA that looked plausible was
actually the middle of a function; calling it faulted on a `movzx` reading `[rax+0x24]`
with a bogus `rax`. The correct entry was a different address entirely, and it was a
thunk.

### When `.pdata` itself is unreadable

Some protected builds encrypt or virtualise the exception directory. The section exists
and has a plausible size, but its bytes are random: every parsed "BeginAddress" lands
outside the code sections. Always sanity-check before trusting it —

```
sample the entries; if fewer than ~90% of BeginAddress values land inside a code section,
the table is not a real RUNTIME_FUNCTION array
```

`pe_tool.py` does this and reports "not backed / unreadable" instead of a page of false
`L1-FAIL`s. Fall back to:

1. **prologue + boundary heuristic** (soft evidence): the candidate starts with a frame
   save (`push`, `sub rsp`, `mov [rsp+x], reg`) *and* the bytes before it end in padding
   (`CC`/`90`) or a `ret`. Two independent signals, still not proof.
2. **known-good cross-checks**: does a decompiled call site call into this address? does
   the prologue disassemble cleanly for a full 16 bytes with no early `ret`?
3. **runtime**: does calling it fault? A mid-function entry faults almost immediately,
   which is the cheapest discriminator of all.

Never let a soft-L1 offset reach a hook without an L3 call test.

## 3. Thunks

A function may be replaced by a 5-byte stub:

```asm
E9 <rel32>      ; jmp  target ;  target = rva + 5 + rel32
```

Rules:

- **Hook the final target**, not the stub. A hook on a stub is installed at an address the
  game never calls.
- Follow recursively — chained stubs exist (`stub -> stub -> body`).
- Guard against loops and out-of-section displacements.
- Record the chain, not just the final value, in the ledger.

```bash
python scripts/pe_tool.py thunk <binary> 0x146C6C0
# 0x146C6C0 -> 0x16BA230
# real target: 0x16BA230   bytes: 89 0d 2e 65 ef 03 ...
```

In `verify` output a thunk shows as `L2-THUNK use 0x...`, which is a directive, not a
failure: use the suggested address.

## 4. Marker strings (IL2CPP plumbing, not gameplay)

Runtime-internal functions are often reachable by the error strings they reference:

- `because generic types cannot have explicit layout.` → metadata type-info cache
- `must be instantiated using the ScriptableObject.CreateInstance method instead of new %s.` → class name path
- `value__` → field enum plumbing

Procedure: find the string, find RIP-relative references to it (`REX + opcode +
modrm(0x05) + disp32`), map each reference back to its function start via `.pdata`,
decompile the top candidates. `scripts/scan_offsets_v2.py` does this; it allows a small
disp tolerance because a long string can be addressed at a split point.

Limits, and they are firm:

- A marker string usually lands in **error formatting** code, not the API. Decompile and
  check the data flow before believing it.
- If the build encrypts metadata and method names (common in protected releases), the
  strings for *gameplay* methods are absent. Do not spend days scanning for them; switch
  to §5 or to a live process.

## 5. Recovering names by cross-version bytecode matching

When you have an older build that still has names (a `.i64`, a `dump.cs`, a public
database) and a newer build that does not:

1. Index every function start of the **new** build from `.pdata`.
2. Export the first N bytes (48 is enough) of every function of the **old** build.
3. **Normalise** before comparing — this is the whole trick:
   - `E8/E9 rel32` → mask 4 bytes
   - `0F 8x rel32` → mask 4 bytes
   - `REX + modrm(0x05) + disp32` (RIP-relative) → mask 4 bytes
   - `REX + B8..BF + imm64` (`movabs`) → mask 8 bytes

   Without masking, matches collapse to ~1 % because every call displacement moved.
   With masking, expect low single-digit percent of all methods — thousands of names.
4. **Keep only unique signatures.** For each signature, count how many functions in the
   new build share it; keep a match only when the count is 1. Small functions share
   prologues and produce false positives by the hundred.

`scripts/build_named_offsets_v2.py` then `scripts/filter_unique_offsets.py` implement this.

Limits: recompiled functions do not match; and a recovered name may itself be obfuscated
(`JIDHLNCONOE`), in which case the name is useless and you need runtime semantics
(§`SKILL.md` §7 Rule 4, or counting hooks).

## 6. Reading a decompiled function for argument shape

The single most useful skill in this whole document. Given a candidate, read what each
parameter is used for:

```c
// decompiled
uintptr_t f(uintptr_t a1, uintptr_t a2) {
    uintptr_t h = *(uintptr_t*)(a2 + 0x20);   // a2 must be an object with a field at 0x20
    uintptr_t l = *(uintptr_t*)(h + 0x10);    // ...
    return g(a1, 0x100D000);                  // a1 is passed straight through
}
```

Inferences you may make:

- A parameter that is dereferenced with a fixed offset is an **object pointer**.
- A parameter used as `array[index]` or compared against a small constant is an **integer**.
- A parameter passed into a class-lookup helper is a **class pointer**, not an RVA.
- A parameter only forwarded unchanged tells you nothing; find its other call sites.

Then confirm with the actual disassembly — `pe_tool.py disasm` — because decompiler
output can hide a `null` check that reveals intent.

## 7. What static analysis cannot tell you

- Whether the function is *safe to call* at a given moment (thread, game state).
- Whether your write lands on the field you think it does.
- Whether the effect you expect is the effect the engine produces.

All three need a live process. Static analysis narrows the candidate set; it never closes
the task.
