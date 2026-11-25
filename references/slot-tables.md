# Slot tables — turning any labelled artifact into an RVA map

The fastest way to map a stripped binary is usually **not** to analyse it. It is to find
another implementation of the same tool for the same game and read how *it* referenced
things.

## 1. Why this works

Modding tools rarely call game functions by hard-coded address. They store the address in
a static data slot once, then call through it:

```c
// decompiled from any tool that has been updated for this patch
lVar15 = FUN_1800170f0();                                  // module base
uVar6  = *(uint64_t *)(lVar15 + DAT_1801fa5b0);            // slot -> game RVA
lVar15 = (*(code *)(lVar15 + _DAT_1801fa5a8))(uVar27, uVar6);
//                                             ^ slot -> game RVA, called
```

Two properties make this a gift:

- The **slot shape** (which data address holds which RVA) is stable across patches far
  more often than the RVA value itself.
- The decompiled code around each slot tells you **what the function is for**, which is the
  part an RVA list never carries.

So: harvest `slot -> RVA -> behaviour`, then **re-verify every RVA against your own target
build**. Values drift; shapes and semantics do not.

## 2. Procedure

### 2.1 Locate the slot region in the other binary

Slots are dense qwords whose values are small integers that fall inside a code section.

```bash
python scripts/pe_tool.py sections <other-binary>
# then, given code sections below 0x20000000, sweep the data section:
python scripts/pe_tool.py slotmap <other-binary> 0x1F8000 0x1FAA00 --src <decompiled-dir>
```

`slotmap` reports, per slot: the stored value, whether it lands in code, whether it is a
thunk (and the thunk target), the first bytes at the target, and which decompiled source
lines reference the slot.

### 2.2 Name the slot by its call site

This is the important step. A slot is only meaningful with the code that reads it. Read
those source lines and answer:

- What is passed as each argument at the *call*?
- What does the caller do with the return value?
- Which feature module is the caller in (file name is a strong hint)?

Record that as the behaviour, e.g.:

| slot | stored RVA | behaviour | caller |
|---|---|---|---|
| `0x1801f9c50` | `0x8D71C70` | `float3* f(out, obj)` — position of an object | ESP, teleport, loot |
| `0x1801f9c60` | `0x117C9F70` | `entity* f(ctx, configId)` | ESP, killaura |
| `0x1801f9fb0` | `0xCD71510` | `bool f(world)` — in-world gate | every module |
| `0x1801f9e18` | `0x1A251FA0` | `float3* f(out, viewport, pos, 1)` — world→screen | ESP, map |
| `0x1801f9e20` | `0x1A2522D0` | thunk → viewport getter | ESP |

The same slot in your target may hold a different number. That is expected.

### 2.3 Verify against your target

```bash
# put the harvested values in a spec file
cat > spec.txt <<'EOF'
GetPosition=0x8D71C70
GetEntityByConfigId=0x117C9F70
InWorld=0xCD71510
WorldToScreen=0x1A251FA0
ViewportGetter=0x1A2522D0
EOF
python scripts/pe_tool.py verify <your-target> spec.txt --json verify.json
```

Read the verdict column, not just the exit code:

- `OK` → proceed to L3.
- `L2-THUNK use 0x...` → use the suggested address.
- `L1-FAIL mid-function` → you copied the wrong slot or the wrong patch; do not "fix" it
  by adding an offset.
- `L0-FAIL not in code section` → the value is a data address, not a function.

### 2.4 Record it

```bash
python scripts/offset_ledger.py set ledger.json --name GetPosition --rva 0x8D71C70 \
    --kind code --level L2 --source "slot 0x1801f9c50 (other-tool dump)" --patch 7.2
```

Two fields matter more than they look: **source** (where the number came from, so the next
person can re-derive it) and **patch** (so a staleness check is possible).

```bash
python scripts/offset_ledger.py stale ledger.json --patch 7.2
```

## 3. The same trick for field offsets

Slots also hold *values* an implementation compared against, which tells you what a field
means without any guesswork. Example shapes worth grepping the other tool's sources for:

- `+ 0x3d4` used as an id passed into a lookup → that offset is a config id.
- `+ 0x490` compared against small integers → that offset is a type enum, and the
  comparisons enumerate the codes (`2` = monster, `0x1F` = avatar, `0x1A` = chest, …).
- `+ 0x268` read from the local player object and fed into the same lookup → own id.

Field offsets drift too, but the *predicate* (which values are legal) does not, which is
what makes a shape test possible — see `pointer-chains.md` §4.

## 4. Failure modes

| Failure | Cause | Guard |
|---|---|---|
| Every harvested RVA fails `verify` | Slot values are stored rebased (absolute VAs) rather than RVAs | Subtract the other binary's image base before comparing |
| Some slots hold `0` | Slot populated at runtime, not in the file | Skip; they are initialised by code you have not run |
| Slot points at a thunk chain | Tool itself follows stubs at runtime | Always use the final target |
| Slot value is a small constant like `0x600000100` | Not an RVA: packed flags or a width/height | Ignore anything outside code sections |
| Behaviour does not match the name you gave it | You named it from the file name, not the call site | Re-read the call site; the call is the evidence |

## 5. Ethics of provenance

Record where every number came from. "I found it in another tool" is a legitimate source
only as a **hint**; the deliverable is your own verified number on your own target. Never
ship a harvested value that has not passed `verify` on the build you are supporting.
