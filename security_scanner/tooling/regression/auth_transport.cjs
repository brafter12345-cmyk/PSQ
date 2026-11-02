const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const sec = path.resolve(__dirname, '../..');
const root = path.join(sec, 'frontend', 'src');
const ts = require(path.join(sec, 'frontend', 'node_modules', 'typescript'));
const mutation = process.argv[2] || '';
let key='synthetic-key', calls=[], currentStatus=200, stateChanges=[], timers=[], sources=[];
const document={querySelector:()=>key===null?null:{content:key}};
const window={location:{origin:'https://example.invalid',reload(){stateChanges.push('reload')}}, CHECKER_MANIFEST:[]};
const fetch=async (url,init)=>{calls.push({url,init});return {status:currentStatus,ok:currentStatus===200,json:async()=>({status:'pending',error:'synthetic error'})}};
function mutate(src, old, replacement) {
 assert.equal(src.split(old).length, 2, 'mutation anchor must occur once');
 return src.replace(old, replacement);
}
function load(file, requires={}) {
 let src=fs.readFileSync(path.join(root,file),'utf8').replaceAll('\r\n','\n');
 if(file==='base.ts') {
   if(mutation==='header') src=mutate(src,"if (key) headers.set('X-Api-Key', key)","if (key) void key");
   if(mutation==='base') src=mutate(src,'const target = withBase(path)','const target = path');
   if(mutation==='origin') {
     src=mutate(src,"if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\\\'))",'if (false)');
     src=mutate(src,'if (new URL(target, window.location.origin).origin !== window.location.origin)','if (false)');
   }
 }
 if(file==='components/scan/ScanProgress.tsx' && mutation==='poll') src=mutate(src,'if (poll) clearInterval(poll)\n            setError', 'if (poll) void poll\n            setError');
 src=src.replaceAll('import.meta.env.BASE_URL',JSON.stringify('/scanner/static/dashboard/'));
 let js=ts.transpileModule(src,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020,jsx:ts.JsxEmit.ReactJSX,esModuleInterop:true}}).outputText;
 let module={exports:{}};
 vm.runInNewContext(js,{module,exports:module.exports,require:n=>requires[n]||require(n),URL,Headers,document,window,fetch,console,setInterval:(fn)=>{timers.push(fn);return timers.length},clearInterval:id=>{timers[id-1]=null},setTimeout:()=>0,EventSource:class {constructor(){sources.push(this)} close(){}}},{filename:file});
 return module.exports;
}
(async()=>{
 const base=load('base.ts');
 await base.apiFetch('/api/test',{method:'POST',redirect:'follow',headers:{'Content-Type':'application/json','X-Custom':'kept'},body:'{}'});
 assert.equal(calls[0].url,'/scanner/api/test'); assert.equal(calls[0].init.headers.get('x-api-key'),key); assert.equal(calls[0].init.headers.get('x-custom'),'kept'); assert.equal(calls[0].init.headers.get('content-type'),'application/json'); assert.equal(calls[0].init.body,'{}'); assert.equal(calls[0].init.redirect,'error');
 key=''; await base.apiFetch('/api/test'); assert.equal(calls[1].init.headers.has('x-api-key'),false);
 key=null; await base.apiFetch('/api/test'); assert.equal(calls[2].init.headers.has('x-api-key'),false);
 key='synthetic-key'; for (const input of ['https://evil.invalid/api','//evil.invalid/api','/\\evil.invalid/api']) assert.throws(()=>base.apiFetch(input),/same-origin/);
 assert.equal(calls.length,3);
 const effects=[]; const react={useEffect:f=>effects.push(f),useState:initial=>[initial,v=>stateChanges.push(v)],useRef:initial=>({current:initial})};
 const jsx={jsx:()=>null,jsxs:()=>null};
 const Scan=load('components/scan/ScanProgress.tsx',{'react':react,'react/jsx-runtime':jsx,'lucide-react':{},'./ScanProgress.module.css':{default:{}},'../../base':base}).default;
 Scan({scanId:'synthetic',domain:'example.invalid'}); effects[1](); sources[0].onerror();
 const tick=timers[0]; assert(tick); currentStatus=200; await tick(); assert(timers[0]); assert(!stateChanges.includes('reload'));
 currentStatus=500; await tick(); assert(timers[0]); assert(stateChanges.includes('synthetic error'));
 currentStatus=401; await tick(); assert.equal(timers[0],null); assert(stateChanges.includes('Request denied (HTTP 401)'));
 effects[1](); sources[1].onerror(); const tick2=timers[1]; currentStatus=403; await tick2(); assert.equal(timers[1],null); assert(stateChanges.includes('Request denied (HTTP 403)'));
 console.log('PASS helper same-origin, redirect, headers and actual polling');
})().catch(e=>{console.error(e);process.exitCode=1});
