// Clean runtime dumper: iterate method array until invalid, no bogus count field.
const MOD="GenshinImpact.exe";
const OUT="D:/GENSHIN/dump7.2/dump_clean.cs";
const GTI=0x527E20;
const MAX_INDEX=200000, NULL_STREAK=4000, MAX_METHODS=256;
function log(s){console.log(s);}
function readable(p){try{p.readU8();return true;}catch(e){return false;}}
function cstr(p){if(!p||p.isNull()||!readable(p))return "";try{const s=p.readUtf8String();return(s&&s.length>0&&s.length<200&&/^[\x20-\x7E]+$/.test(s))?s:"";}catch(e){return "";}}
function main(){
  let mod=null,f=null;
  for(let i=0;i<90;i++){mod=Process.findModuleByName(MOD);if(mod){try{f=new NativeFunction(mod.base.add(GTI),"pointer",["int"]);if(f(0))break;}catch(e){}}Thread.sleep(1000);}
  if(!f){log("not ready");return;}
  const b=mod.base,end=b.add(mod.size);
  function inCode(v){if(v.compare(b)<0||v.compare(end)>=0)return false;const r=v.sub(b).toUInt32();return (r>=0x1000&&r<0x21d2200)||(r>=0x6d2b000&&r<0x1a400000);}
  const file=new File(OUT,"w");
  let dumped=0,methods=0,streak=0;
  const t0=Date.now();
  for(let i=0;i<MAX_INDEX;i++){
    let ti;try{ti=f(i);}catch(e){break;}
    if(!ti||ti.isNull()){if(++streak>NULL_STREAK){log("stop at "+i);break;}continue;}
    streak=0;
    let k;try{k=ti.add(8).readPointer();}catch(e){continue;}
    if(!k||k.isNull()||!readable(k))continue;
    const name=cstr(k.add(0x88).readPointer());
    if(!name)continue;
    file.write(`// TypedefIndex: ${i}\nclass ${name}\n{\n\t// Methods\n`);
    const first=k.add(0x100);
    for(let j=0;j<MAX_METHODS;j++){
      let code;try{code=first.add(j*0x38).readPointer();}catch(e){break;}
      if(!code||code.isNull()||!inCode(code))break;
      file.write(`\t// RVA: 0x${code.sub(b).toString(16).toUpperCase()}\n\tvoid method_${j}();\n`);
      methods++;
    }
    file.write("}\n\n");dumped++;
    if(i%10000===0&&i>0){file.flush();log(`${i} ${dumped} ${methods} ${((Date.now()-t0)/1000).toFixed(0)}s`);}
  }
  file.flush();file.close();
  log(`DONE ${dumped} classes ${methods} methods -> ${OUT}`);
}
setTimeout(main,1500);
