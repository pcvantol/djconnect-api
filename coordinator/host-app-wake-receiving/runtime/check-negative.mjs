/** Actual shipped-module negative boundaries, never native admission. */
import {createRequire} from 'node:module';
import {readFile,writeFile,realpath} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import assert from 'node:assert/strict';
import {root,sha,verifyPackage} from './package-lib.mjs';
const base=await realpath(process.argv[2]),proof=await verifyPackage(base,process.argv[3]);
const req=createRequire(join(root,'package.json')),wranglerReq=createRequire(req.resolve('wrangler')),{Miniflare,Log,LogLevel,convertV4MiniflareOptions}=wranglerReq('miniflare');
const bundle=await readFile(join(base,'receiving.mjs'),'utf8');
const driver=`import entry,{createReceivingService} from './bundle.mjs';
export default {async fetch(request,env){
 let checks=0,providerAttempts=0;
 const check=(value)=>{if(!value)throw Error('preview_negative_boundary');checks++;};
 const denied=(work)=>{let failed=false;try{work();}catch{failed=true;}check(failed);};
 denied(()=>createReceivingService({}));
 denied(()=>createReceivingService({env:{},now:()=>Date.now(),fetcher:fetch,capacity:1}));
 denied(()=>createReceivingService({env:{DB:env.DB},fetcher:fetch,capacity:1}));
 denied(()=>createReceivingService({env:{DB:env.DB},now:()=>Date.now(),capacity:1}));
 denied(()=>createReceivingService({env:{DB:env.DB},now:()=>Date.now(),fetcher:fetch,capacity:0}));
 denied(()=>createReceivingService({env:{DB:env.DB},now:()=>Date.now(),fetcher:fetch,capacity:4097}));
 const paths=['issuer/issue','issuer/status','issuer/withdraw','native/challenge','native/complete','native/status','authorization/resolve','operator/authorize','operator/withdraw','operator/native-policy','operator/native-policy/withdraw','register','wake','status','revoke'];
 const service=createReceivingService({env:{DB:env.DB},now:()=>Date.now(),fetcher:async()=>{providerAttempts++;throw Error('NO_PROVIDER');},capacity:1});
 try{for(const p of paths){const url='https://source-preview.local/v1/push/host-app-wake/'+p;check((await entry.fetch(new Request(url,{method:'POST'}))).status===503);const r=await service.handle(new Request(url,{method:'POST',headers:{'content-type':'application/json'},body:'{}'}));check(r.status>=400);const text=await r.text();check(!text.includes('credential')&&!text.includes('native_verified'));}}
 finally{service.close();}
 check(providerAttempts===0);check((await env.DB.prepare(\"SELECT count(*) n FROM sqlite_master WHERE name LIKE 'host_wake_%'\").first('n'))===0);
 return Response.json({classification:'ACTUAL_PACKAGED_WORKERD_NEGATIVE_BOUNDARIES_ONLY',checks,providerAttempts,productionBindings:false,positiveEnrollment:false,originalClockQualification:false});
}};`;
let egress=0,instance;
try{
 instance=new Miniflare(convertV4MiniflareOptions({workers:[{name:'package-negative',compatibilityDate:proof.compatibility.date,compatibilityFlags:proof.compatibility.flags,modulesRoot:base,modules:[{type:'ESModule',path:join(base,'driver.mjs'),contents:driver},{type:'ESModule',path:join(base,'bundle.mjs'),contents:bundle}],d1Databases:['DB'],outboundService:()=>{egress++;return new Response(null,{status:503});}}],log:new Log(LogLevel.NONE)}));
 const worker=await instance.getWorker('package-negative'),response=await worker.fetch('https://local.test/__package_negative');assert.equal(response.status,200);const result=await response.json();assert.equal(result.checks,53);assert.equal(result.providerAttempts,0);assert.equal(egress,0);result.module_sha256=sha(bundle);result.package_proof_sha256=process.argv[3];result.egress=0;result.positive_native_or_clock_admission=false;
 if(process.argv[4])await writeFile(resolve(process.argv[4]),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
}finally{if(instance)await instance.dispose();}
