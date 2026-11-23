// Runtime validation of candidate IL2CPP API RVAs (Genshin 7.2)
// Called from run_frida.py with CANDIDATES injected.
const MOD = "GenshinImpact.exe";

function log(s) { console.log(s); }
function readable(p) { try { p.readU8(); return true; } catch (e) { return false; } }
function cstr(p) {
  if (!p || p.isNull() || !readable(p)) return "";
  try {
    const s = p.readUtf8String();
    return (s && s.length < 200 && /^[\x20-\x7E]+$/.test(s)) ? s : "";
  } catch (e) { return ""; }
}
function dumpStrings(p, label) {
  if (!p || p.isNull() || !readable(p)) return;
  const parts = [];
  for (let off = 0; off <= 0x60; off += 8) {
    let v;
    try { v = p.add(off).readPointer(); } catch (e) { continue; }
    const s = cstr(v);
    if (s) parts.push(`+0x${off.toString(16)}=${JSON.stringify(s)}`);
  }
  if (parts.length) log(`    ${label}: ${parts.join(" | ")}`);
}

function main() {
  const mod = Process.findModuleByName(MOD);
  if (!mod) { log("[-] module not found"); return; }
  const b = mod.base;
  log(`[+] ${MOD} base=${b} size=0x${mod.size.toString(16)}`);

  let klass = null;
  let getTypeInfoRva = null;

  for (const c of CANDIDATES) {
    const fn = b.add(c.rva);
    log(`\n[*] ${c.name} RVA 0x${c.rva.toString(16).toUpperCase()} -> ${fn}`);
    try {
      if (c.sig === "int") {
        const f = new NativeFunction(fn, "pointer", ["int"]);
        for (const idx of [0, 1, 2, 10]) {
          try {
            const r = f(idx);
            log(`    [${idx}] => ${r}` + (r && !r.isNull() ? ` readable=${readable(r)}` : ""));
            if (r && !r.isNull() && readable(r)) {
              dumpStrings(r, `ret[${idx}]`);
              if (idx === 0 && !klass) { klass = r; getTypeInfoRva = c.rva; }
            }
          } catch (e) { log(`    [${idx}] EX ${e.message}`); }
        }
      } else if (c.sig === "ptr") {
        const f = new NativeFunction(fn, "pointer", ["pointer"]);
        const targets = klass ? [klass, klass.add(0x20)] : [b.add(0x1000)];
        for (const t of targets) {
          try {
            const r = f(t);
            log(`    arg ${t} => ${r} ${cstr(r) ? JSON.stringify(cstr(r)) : ""}`);
          } catch (e) { log(`    arg ${t} EX ${e.message}`); }
        }
      } else if (c.sig === "iter") {
        const f = new NativeFunction(fn, "pointer", ["pointer", "pointer"]);
        if (!klass) { log("    no klass yet"); continue; }
        const it = Memory.alloc(Process.pointerSize);
        Memory.writePointer(it, NULL);
        for (let i = 0; i < 3; i++) {
          try {
            const r = f(klass, it);
            log(`    iter[${i}] => ${r} ${cstr(r) ? JSON.stringify(cstr(r)) : ""}`);
            if (r && !r.isNull()) dumpStrings(r, "item");
          } catch (e) { log(`    iter EX ${e.message}`); break; }
        }
      }
    } catch (e) {
      log(`    BIND EX ${e.message}`);
    }
  }

  log(`\n[+] RESULT: typeInfoRva=${getTypeInfoRva ? "0x" + getTypeInfoRva.toString(16) : "NONE"} klass=${klass}`);
  globalThis._klass = klass;
}
setTimeout(main, 2000);
