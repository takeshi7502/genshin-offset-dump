// Observe candidate functions without calling them: log first args + retval.
// CANDIDATES injected by run_frida.py: [{name, rva}]
const MOD = "GenshinImpact.exe";
const MAXHITS = 4;
function log(s) { console.log(s); }

function main() {
  const mod = Process.findModuleByName(MOD);
  if (!mod) { log("[-] module not found"); return; }
  const b = mod.base;
  log(`[+] base=${b}`);
  let attached = 0;
  for (const c of CANDIDATES) {
    if (!c.rva) continue;
    try {
      const addr = b.add(c.rva);
      const hits = { n: 0 };
      Interceptor.attach(addr, {
        onEnter(args) {
          if (hits.n >= MAXHITS) return;
          hits.n++;
          this.i = hits.n;
          this.a0 = args[0]; this.a1 = args[1]; this.a2 = args[2];
          log(`[${c.name} 0x${c.rva.toString(16)}] #${hits.n} a0=${args[0]} a1=${args[1]} a2=${args[2]}`);
        },
        onLeave(retval) {
          if (this.i) log(`[${c.name}] #${this.i} RET=${retval}`);
        }
      });
      attached++;
    } catch (e) { log(`[-] attach ${c.name}: ${e.message}`); }
  }
  log(`[+] attached ${attached}/${CANDIDATES.length}`);
}
setTimeout(main, 500);
