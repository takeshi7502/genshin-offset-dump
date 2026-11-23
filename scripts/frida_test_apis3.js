const MOD="GenshinImpact.exe";
const C={
  class_get_name_a:0x14DAD3C, class_get_name_b:0x14D327D,
  method_get_name_a:0x14C93C0, method_get_name_b:0x1A2B370,
};
function log(s){console.log(s);}
function readable(p){try{p.readU8();return true;}catch(e){return false;}}
function cstr(p){if(!p||p.isNull()||!readable(p))return "";try{const s=p.readUtf8String();return(s&&s.length>0&&s.length<200&&/^[\x20-\x7E]+$/.test(s))?s:"";}catch(e){return "";}}
function attempt(n){
  const mod=Process.findModuleByName(MOD);
  if(!mod){ if(n<60) setTimeout(()=>attempt(n+1),1000); else log("module timeout"); return; }
  const b=mod.base;
  let f;
  try{f=new NativeFunction(b.add(0x527E20),"pointer",["int"]); if(!f(0)) throw new Error("null");}
  catch(e){ if(n<60) setTimeout(()=>attempt(n+1),1000); else log("api timeout"); return; }
  log("[+] ready base="+b);
  const ti=f(100), k=ti.add(8).readPointer();
  const arr=k.add(0x30).readPointer();
  const m0=(arr&&!arr.isNull())?arr.readPointer():k.add(0x100);
  log(`klass=${k} arr=${arr} m0=${m0} code=${m0.readPointer()}`);
  for(const [name,rva] of Object.entries(C)){
    log(`\n[*] ${name} 0x${rva.toString(16)}`);
    let fn;
    try{fn=new NativeFunction(b.add(rva),"pointer",["pointer"]);}catch(e){log(" bind fail "+e.message);continue;}
    for(const [label,p] of [["klass",k],["method",m0],["ti",ti]]){
      try{const r=fn(p);log(`  ${label}: ${r} '${cstr(r)}'`);}catch(e){log(`  ${label}: EX ${e.message}`);}
    }
  }
}
setTimeout(()=>attempt(0),1500);
