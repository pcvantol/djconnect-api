import {test,expect,vi} from 'vitest';
import {env,runInDurableObject,runDurableObjectAlarm,abortAllDurableObjects,SELF} from 'cloudflare:test';
import cbor from 'cbor';
import * as pki from 'pkijs';
import fixtures from 'djc-assertion-state-fixtures';
import {decryptSecret} from 'djc-existing-crypto';
import {EnrollmentKeyState} from './enrollment-key-state';
const ns=env.SOFTWARE_ENROLLMENT,real=env.ENROLLMENT_COORDINATOR;
const u=v=>Buffer.from(v).toString('base64url'),b64=v=>Buffer.from(v).toString('base64'),text=v=>new TextEncoder().encode(v);
const hash=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const keyA=b64(new Uint8Array(32).fill(11)),keyB=b64(new Uint8Array(32).fill(22));
const denied=async p=>expect(await p).toMatchObject({ok:false});
const clock=async(at,f)=>{vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(at);try{await f();}finally{vi.useRealTimers();}};
const inspect=(s,table)=>runInDurableObject(s,(_i,c)=>c.storage.sql.exec('SELECT value FROM '+table).toArray().map(r=>JSON.parse(r.value)));
const row=async s=>(await inspect(s,'key_state'))[0],op=async s=>(await inspect(s,'enrollment_operation'))[0];
async function software(){const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']),point=new Uint8Array(await crypto.subtle.exportKey('raw',keys.publicKey));return {keys,point,keyId:b64(await hash(point))};}
async function setup(namespace=ns){const s=namespace.get(namespace.idFromName(crypto.randomUUID()));await runInDurableObject(s,i=>{i.env.RECEIPT_ACTIVE_KEY=keyA;i.env.ASSERTION_POLICY_ENABLED='ios-dev-qualification/1';i.env.ASSERTION_POLICY_EXPIRES_AT=String(Date.now()+100*86400000);i.env.ENROLLMENT_POLICY_REVISION='qualification-1';});return s;}
async function request(s,f){const challenge=await s.issueEnrollment({keyId:f.keyId});expect(challenge.ok).toBe(true);return {challenge,input:{keyId:f.keyId,challengeId:challenge.challenge_id,attestation:text(JSON.stringify({point:b64(f.point),nonce:challenge.challenge,receipt:btoa('PUBLIC_SOFTWARE_INITIAL_RECEIPT_NOT_APPLE_ENROLLMENT'),created:Date.now()-1000,deadline:Date.now()+30000}))}};}
async function assertion(f,ch,counter=1,action='recover-key'){
 let auth=new Uint8Array(37);auth.set(await hash(text('ZEML4LPXH4.dev.djconnect.ios')));auth[32]=0xc0;new DataView(auth.buffer).setUint32(33,counter,false);
 auth=Uint8Array.from([...auth,...cbor.encode(new Map([['apple_bundle_version_01','40230'],['apple_validation_category_01',Buffer.from([3,0,0,0])]]))]);
 const nonce=await hash(Uint8Array.from([...auth,...await hash(Buffer.from(ch.client_data,'base64url'))]));
 const sig=pki.createCMSECDSASignature(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},f.keys.privateKey,nonce));
 return {operationId:ch.challenge_id,action,clientData:ch.client_data,assertion:u(cbor.encode(new Map([['signature',Buffer.from(sig)],['authenticatorData',Buffer.from(auth)]])))};
}
test('no HTTP enrollment or public namespace endpoint',async()=>{expect((await SELF.fetch('https://example.test/v1/rendezvous/attestation/register',{method:'POST'})).status).toBe(503);});
test('default facade rejects software enrollment; no implicit fixture selector',async()=>{const f=await software(),s=await setup(real),{input}=await request(s,f),network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('no network'));try{await denied(s.enroll(input));expect(await row(s)).toBeUndefined();expect((await op(s)).status).toBe('challenge');expect(network).not.toHaveBeenCalled();}finally{network.mockRestore();}});
for(const method of ['load','save','install','installInternal','advance','evidence','evidenceInternal','revoke','rotate','arm','locked','tombstone','beforeInstallCommit','didInstallCommit','enrollmentSnapshot','enrollmentOperation','enrollmentPolicy','verifyEnrollment','allowedEvidenceScope','registered'])test('actual facade RPC denies inherited/private helper: '+method,async()=>{const s=await setup();await expect((async()=>s[method]({}))()).rejects.toThrow();expect(await row(s)).toBeUndefined();});
test('software fixture registration commits ciphertext/key and consumes exact nonce together',async()=>{
 const f=await software(),s=await setup(),{input,challenge}=await request(s,f),result=await s.enroll(input),r=await row(s),receipt=await op(s);
 expect(result).toEqual({ok:true,v:'djc-rendezvous/1',key_expires_at:r.expiresAt});expect(r.counter).toBe(0);expect(r.expiresAt-r.createdAt).toBe(30*86400000);
 expect(receipt.status).toBe('registered');expect(receipt.nonce).toBeUndefined();expect(receipt.expiresAt).toBe(challenge.expires_at);
 const encoded=JSON.parse(new TextDecoder().decode(input.attestation)).receipt;expect(JSON.stringify(r)).not.toContain(encoded);expect(JSON.stringify(r)).not.toContain(atob(encoded));
 const decrypted=JSON.parse(await decryptSecret(r.ciphertext,r.nonce,keyA));expect(decrypted.receipt).toBe(encoded);expect(decrypted.context.objectId).toBe(s.id.toString());
 expect(Object.keys(receipt).sort()).toEqual(['id','internalId','keyAddress','createdAt','expiresAt','policyRevision','policyExpiresAt','status','requestDigest','keyExpiresAt'].sort());
 expect(JSON.stringify(receipt)).not.toContain(f.keyId);expect(JSON.stringify(receipt)).not.toContain(challenge.challenge);
});
test('parallel issuance coalesces original nonce/deadline; raw Apple key ID not persisted',async()=>{const f=await software(),s=await setup(),results=await Promise.all(Array.from({length:8},()=>s.issueEnrollment({keyId:f.keyId})));expect(new Set(results.map(v=>v.challenge_id)).size).toBe(1);expect(new Set(results.map(v=>v.expires_at)).size).toBe(1);expect(Buffer.from(results[0].challenge,'base64url').length).toBe(32);expect(JSON.stringify(await op(s))).not.toContain(f.keyId);});
test('different routed key cannot displace original pending challenge',async()=>{const f=await software(),g=await software(),s=await setup(),first=await s.issueEnrollment({keyId:f.keyId});await denied(s.issueEnrollment({keyId:g.keyId}));expect((await op(s)).id).toBe(first.challenge_id);});
test('challenge issue cannot evict an unexpired registered result receipt',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),first=await s.enroll(input),saved=await op(s);await denied(s.issueEnrollment({keyId:f.keyId}));expect(await op(s)).toEqual(saved);expect(await s.enroll(input)).toEqual(first);});
test('exact retry keeps expiry/ciphertext/monotone counter after real software assertion recovery',async()=>{
 const f=await software(),s=await setup(),{input}=await request(s,f),first=await s.enroll(input),before=await row(s),ch=await s.issueAction({action:'recover-key',keyId:f.keyId});
 expect(await s.authorize(await assertion(f,ch))).toMatchObject({ok:true,kind:'recovery-receipt',counter:1,keyExpiresAt:first.key_expires_at});
 expect(await s.enroll(input)).toEqual(first);const after=await row(s);expect(after.counter).toBe(1);expect(after.ciphertext).toBe(before.ciphertext);expect(after.createdAt).toBe(before.createdAt);
});
test('parallel RPC registration inserts one key; retries recover the original result',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);await runInDurableObject(s,(_i,c)=>{c.storage.sql.exec('CREATE TABLE qa_writes (n INTEGER)');c.storage.sql.exec('CREATE TRIGGER qa_insert AFTER INSERT ON key_state BEGIN INSERT INTO qa_writes(n) VALUES(1); END');});const results=await Promise.all(Array.from({length:8},()=>s.enroll(input)));expect(results.some(r=>r.ok)).toBe(true);const first=results.find(r=>r.ok);for(const r of results.filter(r=>r.ok))expect(r).toEqual(first);expect(await runInDurableObject(s,(_i,c)=>c.storage.sql.exec('SELECT COUNT(*) AS n FROM qa_writes').toArray()[0].n)).toBe(1);expect(await s.enroll(input)).toEqual(first);expect((await row(s)).counter).toBe(0);});
test('direct overlapping registration has one active verifier and releases its guard',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);const results=await runInDurableObject(s,i=>Promise.all(Array.from({length:8},()=>i.enroll(input))));expect(results.filter(r=>r.ok).length).toBe(1);expect((await s.enroll(input)).ok).toBe(true);});
for(const [name,change] of [
 ['proof bytes',v=>{v.attestation=Uint8Array.from([...v.attestation,32]);}],['key',v=>{v.keyId=b64(new Uint8Array(32).fill(7));}],['challenge',v=>{v.challengeId=u(new Uint8Array(32).fill(5));}],
])test('changed exact registration retry denied: '+name,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);await s.enroll(input);const before=await row(s),changed={...input};change(changed);await denied(s.enroll(changed));expect(await row(s)).toEqual(before);});
for(const [name,change] of [
 ['extra field',v=>{v.evidence={ok:true};}],['oversize proof',v=>{v.attestation=new Uint8Array(32769);}],['empty proof',v=>{v.attestation=new Uint8Array();}],['wrong proof type',v=>{v.attestation='bad';}],['key spelling',v=>{v.keyId='A'.repeat(42)+'B=';}],
])test('bounded closed request fails before allocation: '+name,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);change(input);await denied(s.enroll(input));expect(await row(s)).toBeUndefined();expect(await op(s)).toEqual(before);});
for(const phase of ['key','receipt'])test('SQL fault after either half rolls back both key and nonce: '+phase,async()=>{
 const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);
 await runInDurableObject(s,(_i,c)=>c.storage.sql.exec(phase==='key'?"CREATE TRIGGER qa_fault BEFORE INSERT ON key_state BEGIN SELECT RAISE(ABORT,'qa'); END":"CREATE TRIGGER qa_fault BEFORE UPDATE ON enrollment_operation WHEN json_extract(NEW.value,'$.status')='registered' BEGIN SELECT RAISE(ABORT,'qa'); END"));
 await runInDurableObject(s,async(i,c)=>{let hits=0;const exec=c.storage.sql.exec.bind(c.storage.sql),spy=vi.spyOn(c.storage.sql,'exec').mockImplementation((...args)=>{try{return exec(...args);}catch(error){hits++;throw error;}});try{expect(await i.enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(hits).toBe(1);}finally{spy.mockRestore();}});expect(await row(s)).toBeUndefined();expect(await op(s)).toEqual(before);await runInDurableObject(s,(_i,c)=>c.storage.sql.exec('DROP TRIGGER qa_fault'));expect((await s.enroll(input)).ok).toBe(true);
});
test('encryption failure preserves pending nonce; repair same operation succeeds',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);await runInDurableObject(s,async i=>{const spy=vi.spyOn(crypto.subtle,'encrypt').mockRejectedValue(new Error('qa encryption'));try{expect(await i.enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(spy).toHaveBeenCalledTimes(1);}finally{spy.mockRestore();}});expect(await row(s)).toBeUndefined();expect(await op(s)).toEqual(before);expect((await s.enroll(input)).ok).toBe(true);});
for(const mutation of ['cancel-operation','policy','policy-revision','challenge-expiry','evidence-expiry','encryption-key','nonce-swap'])test('final SQL guard denies change during actual AES await: '+mutation,async()=>{
 const f=await software(),s=await setup(),{input,challenge}=await request(s,f);await clock(Date.now(),async()=>{
  await runInDurableObject(s,async(i,c)=>{const encrypt=crypto.subtle.encrypt.bind(crypto.subtle),spy=vi.spyOn(crypto.subtle,'encrypt').mockImplementation(async(...a)=>{const ciphertext=await encrypt(...a);if(mutation==='cancel-operation')c.storage.sql.exec('DELETE FROM enrollment_operation');if(mutation==='nonce-swap'){const v=JSON.parse(c.storage.sql.exec('SELECT value FROM enrollment_operation').toArray()[0].value);v.nonce=u(new Uint8Array(32).fill(8));c.storage.sql.exec('UPDATE enrollment_operation SET value=?',JSON.stringify(v));}if(mutation==='policy')i.env.ASSERTION_POLICY_ENABLED='disabled';if(mutation==='policy-revision')i.env.ENROLLMENT_POLICY_REVISION='qualification-2';if(mutation==='challenge-expiry')vi.setSystemTime(challenge.expires_at);if(mutation==='evidence-expiry')vi.setSystemTime(Date.now()+30000);if(mutation==='encryption-key')i.env.RECEIPT_ACTIVE_KEY=keyB;return ciphertext;});try{await denied(i.enroll(input));}finally{spy.mockRestore();}});
  expect(await row(s)).toBeUndefined();
 });
});
test('missing receipt encryption material cannot create an active key',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);await runInDurableObject(s,i=>{i.env.RECEIPT_ACTIVE_KEY=undefined;});await denied(s.enroll(input));expect(await row(s)).toBeUndefined();expect((await op(s)).status).toBe('challenge');});
test('precommit alarm failure creates neither pending challenge nor key',async()=>{const f=await software(),s=await setup();await runInDurableObject(s,async(i,c)=>{const spy=vi.spyOn(c.storage,'setAlarm').mockRejectedValue(new Error('qa'));try{expect(await i.issueEnrollment({keyId:f.keyId})).toEqual({ok:false,error:'service_unavailable'});expect(spy).toHaveBeenCalledTimes(1);}finally{spy.mockRestore();}});expect(await op(s)).toBeUndefined();expect(await row(s)).toBeUndefined();});
test('postcommit alarm failure leaves immutable key/result; exact retry does not install again',async()=>{
 const f=await software(),s=await setup(),{input}=await request(s,f);
 await runInDurableObject(s,async(i,c)=>{const set=c.storage.setAlarm.bind(c.storage);let failed=false;const spy=vi.spyOn(c.storage,'setAlarm').mockImplementation(async(...a)=>{const active=c.storage.sql.exec('SELECT value FROM key_state').toArray().length;if(active&&!failed){failed=true;throw new Error('qa postcommit');}return set(...a);});try{expect(await i.enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(failed).toBe(true);}finally{spy.mockRestore();}});
 const saved=await row(s);expect((await op(s)).status).toBe('registered');expect(await s.enroll(input)).toMatchObject({ok:true,key_expires_at:saved.expiresAt});expect(await row(s)).toEqual(saved);
});
test('retry at original deadline equality denied; no key reset after a fresh challenge',async()=>{const f=await software(),s=await setup(),{input,challenge}=await request(s,f);await s.enroll(input);const before=await row(s);await clock(challenge.expires_at,async()=>{await denied(s.enroll(input));const next=await request(s,f);await denied(s.enroll(next.input));expect((await row(s)).ciphertext).toBe(before.ciphertext);expect((await row(s)).counter).toBe(0);});});
test('authenticated delete atomically erases registration receipt and assertion operations',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);await s.enroll(input);const ch=await s.issueAction({action:'delete-key',keyId:f.keyId});expect((await s.authorize(await assertion(f,ch,1,'delete-key'))).kind).toBe('deleted');const r=await row(s);expect(r.status).toBe('revoked');expect(r.ciphertext).toBeUndefined();expect(await op(s)).toBeUndefined();expect(await inspect(s,'proof_operations')).toEqual([]);await denied(s.enroll(input));});
test('unknown pending nonce is alarm-cleaned without a client retry',async()=>{const f=await software(),s=await setup(),ch=await s.issueEnrollment({keyId:f.keyId});await clock(ch.expires_at,async()=>{await runDurableObjectAlarm(s);expect(await op(s)).toBeUndefined();expect(await row(s)).toBeUndefined();expect(await runInDurableObject(s,(_i,c)=>c.storage.getAlarm())).toBeNull();});});
test('cleanup SQL failure retries without accepting expired proof',async()=>{const f=await software(),s=await setup(),{input,challenge}=await request(s,f);await runInDurableObject(s,(_i,c)=>c.storage.sql.exec("CREATE TRIGGER qa_cleanup BEFORE DELETE ON enrollment_operation BEGIN SELECT RAISE(ABORT,'qa'); END"));await clock(challenge.expires_at,async()=>{await expect(runDurableObjectAlarm(s)).rejects.toThrow();await denied(s.enroll(input));await runInDurableObject(s,(_i,c)=>c.storage.sql.exec('DROP TRIGGER qa_cleanup'));await runInDurableObject(s,i=>i.alarm());expect(await op(s)).toBeUndefined();});});
const settings=s=>runInDurableObject(s,i=>({RECEIPT_ACTIVE_KEY:i.env.RECEIPT_ACTIVE_KEY,ASSERTION_POLICY_ENABLED:i.env.ASSERTION_POLICY_ENABLED,ASSERTION_POLICY_EXPIRES_AT:i.env.ASSERTION_POLICY_EXPIRES_AT,ENROLLMENT_POLICY_REVISION:i.env.ENROLLMENT_POLICY_REVISION}));
test('pending restart retains original nonce and deadline',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s),savedEnv=await settings(s);await abortAllDurableObjects();const reopened=ns.get(s.id);await runInDurableObject(reopened,i=>Object.assign(i.env,savedEnv));expect(await op(reopened)).toEqual(before);expect((await reopened.enroll(input)).ok).toBe(true);});
test('committed restart retains original result and counter after recovery',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),first=await s.enroll(input),ch=await s.issueAction({action:'recover-key',keyId:f.keyId});await s.authorize(await assertion(f,ch,1));const before=await row(s),savedEnv=await settings(s);await abortAllDurableObjects();const reopened=ns.get(s.id);await runInDurableObject(reopened,i=>Object.assign(i.env,savedEnv));expect(await reopened.enroll(input)).toEqual(first);expect(await row(reopened)).toEqual(before);});
for(const f of fixtures.genuine)test('default actual verifier rejects old genuine attestation for a new nonce32: '+f.name,async()=>{const s=await setup(real),ch=await s.issueEnrollment({keyId:f.credential}),network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('no egress'));try{await denied(s.enroll({keyId:f.credential,challengeId:ch.challenge_id,attestation:new Uint8Array(Buffer.from(f.attestation,'base64'))}));expect(await row(s)).toBeUndefined();expect((await op(s)).status).toBe('challenge');expect(network).not.toHaveBeenCalled();}finally{network.mockRestore();}});

for(const name of ['env','ctx','state','#state'])test('actual facade RPC cannot read private property: '+name,async()=>{const s=await setup();await expect((async()=>await s[name])()).rejects.toThrow();});
test('policy change during initial alarm prevents stale challenge creation',async()=>{const f=await software(),s=await setup();await runInDurableObject(s,async(i,c)=>{const set=c.storage.setAlarm.bind(c.storage),spy=vi.spyOn(c.storage,'setAlarm').mockImplementation(async(...a)=>{await set(...a);i.env.ENROLLMENT_POLICY_REVISION='qualification-2';});try{expect(await i.issueEnrollment({keyId:f.keyId})).toEqual({ok:false,error:'registration_rejected'});expect(spy).toHaveBeenCalledTimes(1);}finally{spy.mockRestore();}});expect(await op(s)).toBeUndefined();});
for(const registered of [false,true])test('original enrollment policy cannot be replaced before submit/retry, registered='+registered,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);if(registered)expect((await s.enroll(input)).ok).toBe(true);await runInDurableObject(s,i=>{i.env.ENROLLMENT_POLICY_REVISION='qualification-2';});await denied(s.enroll(input));await denied(s.issueEnrollment({keyId:f.keyId}));expect(Boolean(await row(s))).toBe(registered);});
test('key expiry and finite tombstone purge erase all registration/assertion data',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),registered=await s.enroll(input);await s.issueAction({action:'recover-key',keyId:f.keyId});await clock(registered.key_expires_at,async()=>{await runDurableObjectAlarm(s);const r=await row(s);expect(r.status).toBe('revoked');expect(r.ciphertext).toBeUndefined();expect(await op(s)).toBeUndefined();expect(await inspect(s,'proof_operations')).toEqual([]);});await clock(registered.key_expires_at+120000,async()=>{await runDurableObjectAlarm(s);expect(await row(s)).toBeUndefined();expect(await runInDurableObject(s,(_i,c)=>c.storage.getAlarm())).toBeNull();});});

// Current server-policy availability is distinct from a valid changed saved context.
const unavailablePolicies=[
 ['missing-enabled','ASSERTION_POLICY_ENABLED',undefined],['disabled','ASSERTION_POLICY_ENABLED','disabled'],['wrong-policy','ASSERTION_POLICY_ENABLED','another-policy'],
 ['missing-deadline','ASSERTION_POLICY_EXPIRES_AT',undefined],['malformed-deadline','ASSERTION_POLICY_EXPIRES_AT','bad'],['unsafe-deadline','ASSERTION_POLICY_EXPIRES_AT','9007199254740992'],['negative-deadline','ASSERTION_POLICY_EXPIRES_AT','-1'],['expired-deadline','ASSERTION_POLICY_EXPIRES_AT','0'],
 ['missing-revision','ENROLLMENT_POLICY_REVISION',undefined],['blank-revision','ENROLLMENT_POLICY_REVISION',''],['long-revision','ENROLLMENT_POLICY_REVISION','x'.repeat(129)],['nonstring-revision','ENROLLMENT_POLICY_REVISION',31],
];
for(const [name,field,value] of unavailablePolicies){
 test('unavailable current policy creates no nonce: '+name,async()=>{const f=await software(),s=await setup();await runInDurableObject(s,i=>{i.env[field]=value;});expect(await s.issueEnrollment({keyId:f.keyId})).toEqual({ok:false,error:'service_unavailable'});expect(await op(s)).toBeUndefined();expect(await row(s)).toBeUndefined();});
 test('unavailable current policy skips verifier and exact repair keeps nonce: '+name,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s),saved=await settings(s);await runInDurableObject(s,async(i,c)=>{i.env[field]=value;let calls=0;class CountState extends EnrollmentKeyState{verifyEnrollment(){calls++;throw new Error('verifier must not run');}}expect(await new CountState(c,i.env).enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(calls).toBe(0);});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();await runInDurableObject(s,i=>Object.assign(i.env,saved));const result=await s.enroll(input);expect(result.ok).toBe(true);expect((await op(s)).expiresAt).toBe(before.expiresAt);expect((await row(s)).counter).toBe(0);});
}
test('current policy expiry equality is unavailable without new challenge',async()=>{const f=await software(),s=await setup();await clock(Date.now(),async()=>{await runInDurableObject(s,i=>{i.env.ASSERTION_POLICY_EXPIRES_AT=String(Date.now());});expect(await s.issueEnrollment({keyId:f.keyId})).toEqual({ok:false,error:'service_unavailable'});expect(await op(s)).toBeUndefined();});});
test('repair after original enrollment expiry never invokes verifier or renews nonce',async()=>{const f=await software(),s=await setup(),{input,challenge}=await request(s,f),before=await op(s),saved=await settings(s);await runInDurableObject(s,i=>{i.env.ASSERTION_POLICY_ENABLED='disabled';});expect(await s.enroll(input)).toEqual({ok:false,error:'service_unavailable'});await runInDurableObject(s,i=>Object.assign(i.env,saved));await clock(challenge.expires_at,async()=>{await runInDurableObject(s,async(i,c)=>{let calls=0;class CountState extends EnrollmentKeyState{verifyEnrollment(){calls++;throw new Error('verifier must not run');}}expect(await new CountState(c,i.env).enroll(input)).toEqual({ok:false,error:'registration_rejected'});expect(calls).toBe(0);});expect(await row(s)).toBeUndefined();expect(await op(s)).toEqual(before);});});
for(const field of ['ENROLLMENT_POLICY_REVISION','ASSERTION_POLICY_EXPIRES_AT'])test('valid current policy replacement is still saved-context401: '+field,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);await runInDurableObject(s,i=>{i.env[field]=field==='ENROLLMENT_POLICY_REVISION'?'different-valid-revision':String(Number(i.env[field])+1);});expect(await s.enroll(input)).toEqual({ok:false,error:'registration_rejected'});expect(await s.issueEnrollment({keyId:f.keyId})).toEqual({ok:false,error:'registration_rejected'});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();});
test('postcommit invalid policy is uncertain503 not rollback or replacement',async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),saved=await settings(s);await runInDurableObject(s,async(i,c)=>{const set=c.storage.setAlarm.bind(c.storage),spy=vi.spyOn(c.storage,'setAlarm').mockImplementation(async(...a)=>{await set(...a);if(c.storage.sql.exec('SELECT value FROM key_state').toArray().length)i.env.ASSERTION_POLICY_ENABLED='disabled';});try{expect(await i.enroll(input)).toEqual({ok:false,error:'service_unavailable'});}finally{spy.mockRestore();}});const committed=await row(s),receipt=await op(s);expect(committed.status).toBe('active');expect(committed.counter).toBe(0);expect(receipt.status).toBe('registered');await runInDurableObject(s,i=>Object.assign(i.env,saved));expect(await s.enroll(input)).toEqual({ok:true,v:'djc-rendezvous/1',key_expires_at:committed.expiresAt});expect(await row(s)).toEqual(committed);expect(await op(s)).toEqual(receipt);});

for(const mode of ['live','expiry','rollback'])test('thrown verifier has original deadline priority without storage fallback: '+mode,async()=>{
 const f=await software(),s=await setup(),{input,challenge}=await request(s,f),before=await op(s);
 await clock(Date.now(),async()=>{await runInDurableObject(s,async(i,c)=>{
  let calls=0,readsAfterThrow=0,throwing=false;const exec=c.storage.sql.exec.bind(c.storage.sql),spy=vi.spyOn(c.storage.sql,'exec').mockImplementation((...a)=>{if(throwing)readsAfterThrow++;return exec(...a);});class FaultState extends EnrollmentKeyState{async verifyEnrollment(){calls++;throwing=true;if(mode==='expiry')vi.setSystemTime(challenge.expires_at);if(mode==='rollback')vi.setSystemTime(before.createdAt-1);throw new Error('registration_rejected attestation_unavailable private-server-detail');}}
  expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:mode==='live'?'service_unavailable':'registration_rejected'});expect(calls).toBe(1);expect(readsAfterThrow).toBe(0);spy.mockRestore();
 });});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();expect((await s.enroll(input)).ok).toBe(true);
});
for(const output of [null,undefined,{}, {ok:false,error:'unknown'}, {ok:1}, {ok:false,error:'enrollment_rejected',extra:1}])test('malformed verifier output is server unavailable: '+JSON.stringify(output),async()=>{
 const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);await runInDurableObject(s,async(i,c)=>{let hits=0;class FaultState extends EnrollmentKeyState{verifyEnrollment(){hits++;return output;}}expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(hits).toBe(1);});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
});
for(const [name,value] of [['alphabet','!'.repeat(44)],['padding','='.repeat(44)],['spelling','A'.repeat(42)+'B='],['length','A'],['null',null]])test('malformed key decoding stays explicit rejection: '+name,async()=>{const s=await setup();expect(await s.issueEnrollment({keyId:value})).toEqual({ok:false,error:'registration_rejected'});expect(await op(s)).toBeUndefined();expect(await row(s)).toBeUndefined();});

for(const value of [null,[],{},{name:'RegistrationRejected',message:'registration_rejected'},'service_unavailable'])test('untrusted thrown values never become expected rejection: '+JSON.stringify(value),async()=>{const f=await software(),s=await setup(),{input}=await request(s,f);await runInDurableObject(s,async(i,c)=>{let hits=0;class FaultState extends EnrollmentKeyState{verifyEnrollment(){hits++;throw value;}}expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(hits).toBe(1);});expect(await row(s)).toBeUndefined();});
for(const value of [{ok:false,error:'enrollment_rejected'},{ok:false,error:'attestation_unavailable'}])test('exact closed verifier denial keeps domain classification: '+value.error,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);await runInDurableObject(s,async(i,c)=>{class FaultState extends EnrollmentKeyState{verifyEnrollment(){return value;}}expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:value.error==='enrollment_rejected'?'registration_rejected':'attestation_unavailable'});});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();});

for(const [name,result] of [['negative-array',Object.assign([],{ok:false,error:'enrollment_rejected'})],['positive-array',Object.assign([],{ok:true,evidence:{}})],['evidence-array',{ok:true,evidence:[]}],['semantic-bad-point',{ok:true,evidence:{publicPoint:new Uint8Array([1]),initialReceipt:new Uint8Array([1])}}]])test('verifier envelope rejects arrays but retains semantic validation401: '+name,async()=>{const f=await software(),s=await setup(),{input}=await request(s,f),before=await op(s);await runInDurableObject(s,async(i,c)=>{let hits=0;class FaultState extends EnrollmentKeyState{verifyEnrollment(){hits++;return result;}}expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:name==='semantic-bad-point'?'registration_rejected':'service_unavailable'});expect(hits).toBe(1);});expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();});


// Reached default-verifier callback faults; no software-positive or native claim.
for(const fault of ['sqlite-read','policy-unavailable'])for(const at of [1,2,3])test('default verifier preserves transient internal snapshot fault503: '+fault+' read'+at,async()=>{
 const f=await software(),s=await setup(real),{input}=await request(s,f),before=await op(s);
 const result=await runInDurableObject(s,async(i,c)=>{
  let snapshots=0,hits=0;
  class FaultState extends EnrollmentKeyState{
   enrollmentSnapshot(){
    snapshots++;
    if(snapshots===at){
     hits++;
     if(fault==='sqlite-read')c.storage.sql.exec('SELECT value FROM qa_missing_snapshot_table');
     const saved=this.env.ASSERTION_POLICY_ENABLED;this.env.ASSERTION_POLICY_ENABLED='disabled';
     try{return super.enrollmentSnapshot();}finally{this.env.ASSERTION_POLICY_ENABLED=saved;}
    }
    return super.enrollmentSnapshot();
   }
  }
  const result=await new FaultState(c,i.env).enroll(input);
  expect(hits).toBe(1);return result;
 });
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
 // Healthy invalid proof remains a sender rejection; no replacement challenge.
 expect(await s.enroll(input)).toEqual({ok:false,error:'registration_rejected'});
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
 expect(result).toEqual({ok:false,error:'service_unavailable'});
});

for(const mode of ['live','expiry','rollback'])test('default verifier callback failure respects known original window: '+mode,async()=>{
 const f=await software(),s=await setup(real),{input,challenge}=await request(s,f),before=await op(s);
 await clock(Date.now(),async()=>{
  await runInDurableObject(s,async(i,c)=>{
   let reads=0,hits=0,afterFault=0,faulted=false;
   const exec=c.storage.sql.exec.bind(c.storage.sql),spy=vi.spyOn(c.storage.sql,'exec').mockImplementation((...args)=>{if(faulted)afterFault++;return exec(...args);});
   class FaultState extends EnrollmentKeyState{
    enrollmentSnapshot(){reads++;if(reads===3){hits++;if(mode==='expiry')vi.setSystemTime(challenge.expires_at);if(mode==='rollback')vi.setSystemTime(before.createdAt-1);faulted=true;throw new Error('registration_rejected attestation_unavailable private marker');}return super.enrollmentSnapshot();}
   }
   try{expect(await new FaultState(c,i.env).enroll(input)).toEqual({ok:false,error:mode==='live'?'service_unavailable':'registration_rejected'});expect(hits).toBe(1);expect(afterFault).toBe(0);}finally{spy.mockRestore();}
  });
 });
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
});
test('default verifier retains typed saved-context rejection instead of promoting to503',async()=>{
 const f=await software(),s=await setup(real),{input}=await request(s,f),before=await op(s);
 await runInDurableObject(s,async(i,c)=>{
  let reads=0,hits=0;
  class ReplacedContext extends EnrollmentKeyState{
   enrollmentSnapshot(){reads++;if(reads===3){hits++;const saved=this.env.ENROLLMENT_POLICY_REVISION;this.env.ENROLLMENT_POLICY_REVISION='different-valid-revision';try{return super.enrollmentSnapshot();}finally{this.env.ENROLLMENT_POLICY_REVISION=saved;}}return super.enrollmentSnapshot();}
  }
  expect(await new ReplacedContext(c,i.env).enroll(input)).toEqual({ok:false,error:'registration_rejected'});expect(hits).toBe(1);
 });
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
});

// The existing SOFTWARE fixture invokes the actual shared engine's post-core digest.
for(const kind of ['Error','DOMException','lookalike','undefined'])test('reached enrollment point digest internal503 keeps original pending state and explicit repair: '+kind,async()=>{
 const f=await software(),s=await setup(),{input,challenge}=await request(s,f),before=await op(s);
 await runInDurableObject(s,async i=>{
  const cause=kind==='Error'?new Error('registration_rejected attestation_unavailable PRIVATE'):kind==='DOMException'?new DOMException('PRIVATE','DataError'):kind==='lookalike'?{name:'RegistrationRejected',message:'registration_rejected'}:undefined;
  const original=crypto.subtle.digest.bind(crypto.subtle);let hits=0;
  const spy=vi.spyOn(crypto.subtle,'digest').mockImplementation(async(...args)=>{if(args[0]==='SHA-256'&&Buffer.from(args[1]).equals(Buffer.from(f.point))){hits++;throw cause;}return original(...args);});
  try{expect(await i.enroll(input)).toEqual({ok:false,error:'service_unavailable'});expect(hits).toBe(1);}finally{spy.mockRestore();}
 });
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
 const repaired=await s.enroll(input),registered=await op(s),key=await row(s);expect(repaired.ok).toBe(true);expect(registered.status).toBe('registered');expect(registered.expiresAt).toBe(challenge.expires_at);expect(registered.createdAt).toBe(before.createdAt);expect(key.counter).toBe(0);
});
for(const mode of ['expiry','rollback'])test('reached enrollment point digest failure keeps original window and zero catch SQL: '+mode,async()=>{
 const f=await software(),s=await setup(),{input,challenge}=await request(s,f),before=await op(s);
 await clock(Date.now(),async()=>runInDurableObject(s,async(i,c)=>{
  let hits=0,afterFault=0,faulted=false;const exec=c.storage.sql.exec.bind(c.storage.sql),original=crypto.subtle.digest.bind(crypto.subtle);
  const sql=vi.spyOn(c.storage.sql,'exec').mockImplementation((...a)=>{if(faulted)afterFault++;return exec(...a);});
  const digest=vi.spyOn(crypto.subtle,'digest').mockImplementation(async(...a)=>{if(a[0]==='SHA-256'&&Buffer.from(a[1]).equals(Buffer.from(f.point))){hits++;vi.setSystemTime(mode==='expiry'?challenge.expires_at:before.createdAt-1);faulted=true;throw new Error('registration_rejected PRIVATE');}return original(...a);});
  try{expect(await i.enroll(input)).toEqual({ok:false,error:'registration_rejected'});expect(hits).toBe(1);expect(afterFault).toBe(0);}finally{digest.mockRestore();sql.mockRestore();}
 }));
 expect(await op(s)).toEqual(before);expect(await row(s)).toBeUndefined();
});
