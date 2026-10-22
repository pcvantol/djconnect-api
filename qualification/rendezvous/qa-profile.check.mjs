// Public synthetic positives, actual signatures/CMS/SQLite. No Apple/native claim.
import {test,expect} from 'vitest';
import cbor from 'cbor';import * as pki from 'pkijs';
import {qualifyAssertionCore} from './app-attest-core-candidate.mjs';
import {qualifyAssertionCore as productionCore} from './app-attest-core-candidate.production.mjs';
import {qualifySyntheticReceipt,qualifyReceiptEvidence} from './receipt-cms-candidate.mjs';
import {qualifySyntheticReceipt as productionCms} from './receipt-cms-candidate.production.mjs';
import fixtures from './qa-profile-cms-fixtures.json';
const qaApp='ZEML4LPXH4.dev.djconnect.ios.vibecastqa',prodApp='ZEML4LPXH4.dev.djconnect.ios';
const bytes=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0)),utf8=v=>new TextEncoder().encode(v);
const sha=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const concat=(a,b)=>Uint8Array.from([...a,...b]);
async function signed(app,build){
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const point=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)),client=utf8('saved QA software challenge');
 const auth=new Uint8Array(37);auth.set(await sha(utf8(app)));auth[32]=0xc0;new DataView(auth.buffer).setUint32(33,1,false);
 const properties=new Map([['apple_bundle_version_01',build],['apple_validation_category_01',Buffer.from([3,0,0,0])]]);
 const data=concat(auth,new Uint8Array(cbor.encode(properties))),nonce=await sha(concat(data,await sha(client)));
 const signature=new Uint8Array(pki.createCMSECDSASignature(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,nonce)));
 return {proof:new Uint8Array(cbor.encode(new Map([['signature',Buffer.from(signature)],['authenticatorData',Buffer.from(data)]]))),point,client};
}
for(const [app,build,qa,production]of [[qaApp,'40408',true,false],[prodApp,'40408',false,false],[prodApp,'40230',false,true],[qaApp,'40230',false,false],[qaApp,'40407',false,false],[qaApp,'40409',false,false],['OTHER.dev.djconnect.ios.vibecastqa','40408',false,false]]){
 test('QA profile correctly signed app/build '+app+'/'+build,async()=>{const f=await signed(app,build);expect(Boolean(await qualifyAssertionCore(f.proof,f.client,f.point,0))).toBe(qa);expect(Boolean(await productionCore(f.proof,f.client,f.point,0))).toBe(production);});
}
for(const variant of ['replay','clientData','signature'])test('QA profile synthetic assertion preserves '+variant,async()=>{const f=await signed(qaApp,'40408');if(variant==='clientData')f.client[0]^=1;if(variant==='signature'){const object=cbor.decodeFirstSync(Buffer.from(f.proof),{preferMap:true});object.get('signature')[10]^=1;f.proof=new Uint8Array(cbor.encode(object));}expect(await qualifyAssertionCore(f.proof,f.client,f.point,variant==='replay'?1:0)).toBeNull();});
for(const label of ['qa','production']){
 const raw=fixtures.cases[label];const value=()=>({...raw,...Object.fromEntries(['encoded','attestedCert','clientData','anchor'].map(k=>[k,bytes(raw[k])]))});
 test('QA profile independently signed CMS app '+label,async()=>{expect(Boolean(await qualifySyntheticReceipt(value()))).toBe(label==='qa');expect(Boolean(await productionCms(value()))).toBe(label==='production');});
 for(const field of ['attestedCert','clientData'])test('QA profile signed CMS bound '+label+'/'+field,async()=>{const v=value();v[field][0]^=1;expect(await qualifySyntheticReceipt(v)).toBeNull();});
 test('QA profile synthetic CMS cannot change fixed real root '+label,async()=>{const v=value();expect(await qualifyReceiptEvidence(v.encoded,v.attestedCert,v.clientData,v.anchor)).toBeNull();});
}
// The full derived shared suite additionally reaches actual router -> enrollment
// -> assertion -> transaction and encrypted receipt SQLite, not a string audit.
import {env,runInDurableObject} from 'cloudflare:test';
import {AssertionKeyState} from './assertion-key-state.ts';
const b64=v=>btoa(String.fromCharCode(...v));
for(const policy of ['ios-dev-qualification/1','other'])test('QA profile old policy environment cannot issue challenge '+policy,async()=>{const s=env.ENROLLMENT_COORDINATOR.get(env.ENROLLMENT_COORDINATOR.idFromName(crypto.randomUUID()));const key=b64(new Uint8Array(32));const r=await runInDurableObject(s,(_i,ctx)=>new AssertionKeyState(ctx,{ASSERTION_POLICY_ENABLED:policy,ASSERTION_POLICY_EXPIRES_AT:String(Date.now()+60000)}).issue({keyId:key,action:'recover-key'}));expect(r.ok).toBe(false);});
