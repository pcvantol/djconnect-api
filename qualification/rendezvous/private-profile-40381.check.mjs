import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,chmod,readFile,writeFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import cbor from 'cbor';
import * as pki from 'pkijs';
import {sourceSnapshot,startLocal40381Runtime,repo} from './local-native-runtime.mjs';
import {CORE,PROFILE,derive40381,stage40381,check40381Graph,registrationRecoverController} from './private-profile-40381.mjs';
const require=createRequire(import.meta.url),V='djc-rendezvous/1';
async function scratch(run){const p=await mkdtemp(join(tmpdir(),'djc-profile-40381-check-'));await chmod(p,0o700);try{return await run(p);}finally{await rm(p,{recursive:true,force:true});}}
const body=v=>Buffer.from(JSON.stringify({v:V,...v}));
const key=Buffer.alloc(32,8).toString('base64'),id=Buffer.alloc(32,9).toString('base64url');

test('one fixed build delta only; already changed/ambiguous/unrecognized cores reject',async()=>{
 const original=await readFile(join(repo,CORE)),derived=derive40381(original);
 assert.equal(derived.toString().replace("const BUILDS = new Set(['40381']);","const BUILDS = new Set(['40227', '40228', '40230']);"),original.toString());
 for(const bytes of [derived,Buffer.from(original.toString().replace("'40230'","'other'")),Buffer.concat([original,original])])assert.throws(()=>derive40381(bytes));
});
test('private closed copied tree detects changed/extra/symlink files; graph rejects original core',async()=>scratch(async p=>{
 const snapshot=await sourceSnapshot(),stage=await stage40381(snapshot,repo,p);await stage.verify();
 const core=join(stage.root,CORE),original=await readFile(core);await writeFile(core,'changed');await assert.rejects(stage.verify());await writeFile(core,original);
 await writeFile(join(stage.root,'extra.mjs'),'extra',{mode:0o600});await assert.rejects(stage.verify());await rm(join(stage.root,'extra.mjs'));
 await rm(core);await symlink(join(repo,CORE),core);await assert.rejects(stage.verify());await rm(core);await writeFile(core,original,{mode:0o600});await stage.verify();
 const names=[CORE,'qualification/rendezvous/enrollment-evidence-candidate.mjs','qualification/rendezvous/assertion-key-state.ts'];
 const metadata={inputs:Object.fromEntries(names.map(n=>[join(stage.root,n),{}]))};check40381Graph(metadata,stage,snapshot,repo,p);
 const bad=structuredClone(metadata);bad.inputs[join(repo,CORE)]={};assert.throws(()=>check40381Graph(bad,stage,snapshot,repo,p));
 delete metadata.inputs[join(stage.root,CORE)];assert.throws(()=>check40381Graph(metadata,stage,snapshot,repo,p));
}));
test('controller admits one same-key register/recover sequence, preserving exact input bytes',async()=>{
 const calls=[],client=Buffer.from('synthetic exact action bytes').toString('base64url');
 const send=registrationRecoverController(async(route,bytes)=>{calls.push({route,bytes});return Response.json(calls.length===1?{v:V,challenge_id:id}:calls.length===3?{v:V,challenge_id:id,client_data:client}:{v:V,ok:true});});
 const packets=[['/attestation/challenge',body({key_id:key,action:'register'})],['/attestation/register',body({key_id:key,challenge_id:id,attestation:'AA'})],['/attestation/challenge',body({key_id:key,action:'recover-key'})],['/attestation/recover',body({key_id:key,challenge_id:id,client_data:client,assertion:'AA'})]];
 for(const [route,bytes]of packets)assert.equal((await send(route,bytes)).status,200);
 for(let n=0;n<4;n++)assert.equal(calls[n].bytes,packets[n][1]);
 await assert.rejects(send(...packets[0]));assert.equal(calls.length,4);
});
test('controller refuses other routes, key changes, proof retries and concurrent reservations',async()=>{
 for(const route of ['/create','/submit-challenge','/submit','/attestation/delete']){
  let calls=0;const send=registrationRecoverController(async()=>{calls++;return Response.json({});});
  await assert.rejects(send(route,body({key_id:key,action:'register'})));assert.equal(calls,0);
 }
 for(const change of ['key','challenge','action']){
  let calls=0;const send=registrationRecoverController(async()=>{calls++;return Response.json({v:V,challenge_id:id});});
  await send('/attestation/challenge',body({key_id:key,action:'register'}));
  const packet={key_id:change==='key'?Buffer.alloc(32,4).toString('base64'):key,challenge_id:change==='challenge'?'other':id,attestation:'AA'};
  await assert.rejects(send(change==='action'?'/attestation/delete':'/attestation/register',body(packet)));assert.equal(calls,1);
 }
 let release;const pending=new Promise(r=>{release=r;});let calls=0;
 const send=registrationRecoverController(async()=>{calls++;await pending;return Response.json({v:V,error:'invalid_sender_proof'},{status:401});});
 const first=send('/attestation/challenge',body({key_id:key,action:'register'}));
 await assert.rejects(send('/attestation/challenge',body({key_id:key,action:'register'})));release();assert.equal((await first).status,401);
 await assert.rejects(send('/attestation/challenge',body({key_id:key,action:'register'})));assert.equal(calls,1);
});

test('signed P256 assertion software fixtures distinguish both build policies and preserve crypto denials',async()=>scratch(async p=>{
 const snapshot=await sourceSnapshot(),stage=await stage40381(snapshot,repo,p);
 // Node software-fixture loader: bind imports to the SAME installed modules as
 // the original core. This is a software fixture, not the runtime bundle.
 // Only import addresses change here; the runtime's actual graph is tested below.
 let code=await readFile(join(stage.root,CORE),'utf8');
 for(const name of ['cbor','asn1js','pkijs'])code=code.replace("from '"+name+"'","from "+JSON.stringify(pathToFileURL(require.resolve(name)).href));
 code=code.replace("from './worker-path-candidate.mjs'","from "+JSON.stringify(pathToFileURL(join(repo,'qualification/rendezvous/worker-path-candidate.mjs')).href));
 const out=join(p,'node-fixture-core.mjs');await writeFile(out,code,{mode:0o600});
 const baseline=await import(pathToFileURL(join(repo,CORE)).href),variant=await import(pathToFileURL(out).href);
 const hash=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
 const combine=(a,b)=>Uint8Array.from([...a,...b]);
 async function sign(build,change=()=>{}){
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const point=new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey)),client=Buffer.from('synthetic saved client data');
  const auth=new Uint8Array(37);auth.set(await hash(Buffer.from('ZEML4LPXH4.dev.djconnect.ios')));auth[32]=0xc0;new DataView(auth.buffer).setUint32(33,1,false);
  const ext=new Map([['apple_bundle_version_01',build],['apple_validation_category_01',Buffer.from([3,0,0,0])]]);change(auth,ext);
  // Wait for the Node26 encoder stream; synchronous encode can return just its header.
  const data=combine(auth,await cbor.encodeAsync(ext)),nonce=await hash(combine(data,await hash(client)));
  const sig=pki.createCMSECDSASignature(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,nonce));
  return {proof:await cbor.encodeAsync(new Map([['signature',Buffer.from(sig)],['authenticatorData',Buffer.from(data)]])),point,client};
 }
 const check=(fn,f,previous=0)=>fn(f.proof,f.client,f.point,previous);
 const fresh=await sign('40381');assert.equal((await check(variant.qualifyAssertionCore,fresh))?.counter,1);assert.equal(await check(baseline.qualifyAssertionCore,fresh),null);
 for(const build of ['40227','40228','40230']){const f=await sign(build);assert.equal((await check(baseline.qualifyAssertionCore,f))?.counter,1);assert.equal(await check(variant.qualifyAssertionCore,f),null);}
 for(const mutate of [(a)=>{a[0]^=1;},a=>{a[32]=0x40;},(_a,e)=>{e.set('apple_validation_category_01',Buffer.from([4,0,0,0]));}])assert.equal(await check(variant.qualifyAssertionCore,await sign('40381',mutate)),null);
 for(const previous of [1,2,-1,0xffffffff])assert.equal(await check(variant.qualifyAssertionCore,fresh,previous),null);
 assert.equal(await check(variant.qualifyAssertionCore,{...fresh,client:Buffer.from('different')}),null);
 const decoded=cbor.decodeFirstSync(fresh.proof,{preferMap:true});decoded.get('signature')[10]^=1;
 assert.equal(await check(variant.qualifyAssertionCore,{...fresh,proof:await cbor.encodeAsync(decoded)}),null);
}));

test('actual fixed40381 private workerd keeps120s/default-genuine negatives/zero keys and terminates failed experiment', {timeout:60000},async()=>{
 const runtime=await startLocal40381Runtime();
 try{
  assert.equal(runtime.private_profile.id,PROFILE.id);assert.equal(runtime.private_profile.native_run_admitted,false);await runtime.verifySources();
  const response=await runtime.request('/attestation/challenge',body({key_id:key,action:'register'}));assert.equal(response.status,200);const challenge=await response.json();
  const before=await runtime.enrollmentObservation(key);assert.deepEqual(before.keys,[{n:0}]);assert.equal(before.operations.length,1);
  const op=JSON.parse(before.operations[0].value);assert.equal(op.expiresAt-op.createdAt,120000);
  assert.equal((await runtime.request('/attestation/register',body({key_id:key,challenge_id:challenge.challenge_id,attestation:'AA'}))).status,401);
  assert.deepEqual(await runtime.enrollmentObservation(key),before);assert.deepEqual(runtime.egressObservation(),{allowed:0,denied:0});
  await assert.rejects(runtime.request('/attestation/challenge',body({key_id:key,action:'register'})));
  console.log(JSON.stringify({scope:'PRIVATE_40381_PREPARED_SOFTWARE_AND_ACTUAL_GENUINE_NEGATIVE_NOT_NATIVE_ADMISSION',result:'PASS',api_sha:runtime.snapshot.head,profile:runtime.private_profile,bundle_sha256:runtime.bundle_sha256,installed_keys:0,outbound_attempts:0}));
 }finally{await runtime.stop();}
});
