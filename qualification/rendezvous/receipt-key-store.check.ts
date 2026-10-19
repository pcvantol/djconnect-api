import {test,expect,vi} from 'vitest';
import {env,runInDurableObject,runDurableObjectAlarm,abortAllDurableObjects,SELF} from 'cloudflare:test';
import type {ReceiptKeyStore,StoreEnv,StoreMaterial} from './receipt-key-store';
const namespace=(env as unknown as {RECEIPT_KEY_STORE:DurableObjectNamespace<ReceiptKeyStore>}).RECEIPT_KEY_STORE;
const DAY=86400000;
const denied=async(value:Promise<{ok:boolean}>)=>{expect((await value).ok).toBe(false);};
const keyA=btoa(String.fromCharCode(...new Uint8Array(32).fill(11)));
const keyB=btoa(String.fromCharCode(...new Uint8Array(32).fill(22)));
const keyC=btoa(String.fromCharCode(...new Uint8Array(32).fill(33)));
const stub=()=>namespace.get(namespace.idFromName(crypto.randomUUID()));
const material=():StoreMaterial=>{const now=Date.now();return {keyAddress:'a'.repeat(64),appPolicy:'ios-dev-qualification/1',environment:'development',publicPoint:btoa(String.fromCharCode(4,...new Uint8Array(64).fill(1))),receipt:btoa('PUBLIC_SYNTHETIC_RECEIPT_FOR_STORAGE_ONLY'),receiptCreatedAt:now-1000,challengeCreatedAt:now-1000,challengeExpiresAt:now+119000,operationId:crypto.randomUUID(),requestDigest:'b'.repeat(64)};};
const setKeys=(s:DurableObjectStub<ReceiptKeyStore>,active?:string,previous?:string)=>runInDurableObject(s,(instance)=>{const e=(instance as unknown as {env:StoreEnv}).env;e.RECEIPT_ACTIVE_KEY=active;e.RECEIPT_PREVIOUS_KEY=previous;});
const row=(s:DurableObjectStub<ReceiptKeyStore>)=>runInDurableObject(s,(_i,state)=>state.storage.sql.exec<{value:string}>('SELECT value FROM key_state WHERE id=1').toArray().map(v=>JSON.parse(v.value))[0]);
const change=(s:DurableObjectStub<ReceiptKeyStore>,f:(r:any)=>any)=>runInDurableObject(s,(_i,state)=>{const r=state.storage.sql.exec<{value:string}>('SELECT value FROM key_state WHERE id=1').toArray()[0];state.storage.sql.exec('UPDATE key_state SET value=? WHERE id=1',JSON.stringify(f(JSON.parse(r.value))));});
const clock=async(at:number,body:()=>Promise<void>)=>{vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(at);try{await body();}finally{vi.useRealTimers();}};
test('no public enrollment/storage endpoint',async()=>{expect((await SELF.fetch('https://example.test/attestation/register',{method:'POST'})).status).toBe(503);});
test('actual SQLite contains encrypted evidence and finite context, never plaintext',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const result=await s.install(m);const r=await row(s);
 expect(result.scope).toBe('STORE_ONLY_NO_ENROLLMENT');expect(r.status).toBe('active');expect(r.expiresAt-r.createdAt).toBe(30*DAY);
 expect(JSON.stringify(r)).not.toContain(m.receipt);expect(JSON.stringify(r)).not.toContain(atob(m.receipt));expect(r.ciphertext).toBeTruthy();expect(atob(r.nonce).length).toBe(12);
 expect((await s.evidence()).receipt).toBe(m.receipt);expect(await runInDurableObject(s,(_i,state)=>state.storage.getAlarm())).toBe(m.challengeExpiresAt);
});
test('exact enrollment retry keeps expiry/counter/ciphertext',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const first=await s.install(m);await s.advance(2);const before=await row(s);expect((await s.install(m)).duplicate).toBe(true);const after=await row(s);
 expect(after.expiresAt).toBe(first.expiresAt);expect(after.counter).toBe(2);expect(after.ciphertext).toBe(before.ciphertext);
});
test('different operation/digest cannot overwrite active row',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);await s.install(m);const before=await row(s);
 await denied(s.install({...m,operationId:crypto.randomUUID()}));await denied(s.install({...m,requestDigest:'c'.repeat(64)}));expect(await row(s)).toEqual(before);
});
for(const [name,update] of [
 ['missing-key',undefined],['invalid-short-key',btoa('short')],['noncanonical-key',keyA.replace(/=$/,'')],
] as const){test('encryption fails closed before commit: '+name,async()=>{const s=stub();await setKeys(s,update);await denied(s.install(material()));expect(await row(s)).toBeUndefined();});}
for(const [name,mutate] of [
 ['stale-receipt',(m:StoreMaterial)=>{m.receiptCreatedAt=Date.now()-300001;}],['future-receipt',(m:StoreMaterial)=>{m.receiptCreatedAt=Date.now()+60000;}],
 ['expired-challenge',(m:StoreMaterial)=>{m.challengeExpiresAt=Date.now();}],['too-long-challenge',(m:StoreMaterial)=>{m.challengeExpiresAt=m.challengeCreatedAt+120001;}],
 ['invalid-key-id',(m:StoreMaterial)=>{m.keyAddress='invalid';}],['wrong-app-policy',(m:StoreMaterial)=>{m.appPolicy='unapproved';}],
 ['too-large-receipt',(m:StoreMaterial)=>{m.receipt=btoa('a'.repeat(16385));}],
] as const){test('stored material bounds: '+name,async()=>{const s=stub();await setKeys(s,keyA);const m=material();mutate(m);await denied(s.install(m));expect(await row(s)).toBeUndefined();});}
test('SQL failure rolls back complete registration; original bounded retry can commit',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);await runInDurableObject(s,(_i,state)=>{state.storage.sql.exec("CREATE TRIGGER qa_fail BEFORE INSERT ON key_state BEGIN SELECT RAISE(ABORT,'qualification_write_failure'); END");});
 await denied(s.install(m));expect(await row(s)).toBeUndefined();await runInDurableObject(s,(_i,state)=>{state.storage.sql.exec('DROP TRIGGER qa_fail');});expect((await s.install(m)).duplicate).toBe(false);
});
test('enrollment operation receipt is erased at its original deadline',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);
 await clock(m.challengeExpiresAt,async()=>{await s.evidence();const r=await row(s);expect(r.operationId).toBeUndefined();expect(r.requestDigest).toBeUndefined();expect(r.challengeExpiresAt).toBeUndefined();expect(r.expiresAt).toBe(accepted.expiresAt);await denied(s.install(m));});
});
for(const field of ['ciphertext','nonce','keyVersion','keyAddress','appPolicy','environment','createdAt','expiresAt','receiptCreatedAt','objectId','publicPoint']){
 test('tampered authenticated context denied: '+field,async()=>{const s=stub();await setKeys(s,keyA);await s.install(material());await change(s,r=>({...r,[field]:typeof r[field]==='number'?r[field]+1:r[field]+'X'}));await denied(s.evidence());});
}
test('whole row transplanted into another DO is denied',async()=>{
 const a=stub(),b=stub();await setKeys(a,keyA);await setKeys(b,keyA);await a.install(material());await b.install({...material(),keyAddress:'c'.repeat(64)});const foreign=await row(a);await change(b,()=>foreign);await denied(b.evidence());
 await change(b,r=>({...r,objectId:b.id.toString()}));await denied(b.evidence());
});
test('wrong/missing decryption key denied; previous key supports bounded rotation',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);const old=await row(s);await setKeys(s,keyB);await denied(s.evidence());await setKeys(s,undefined);await denied(s.evidence());await setKeys(s,keyB,keyA);expect((await s.evidence()).receipt).toBe(m.receipt);expect((await s.rotate()).expiresAt).toBe(accepted.expiresAt);const next=await row(s);expect(next.keyVersion).not.toBe(old.keyVersion);expect(next.nonce).not.toBe(old.nonce);await setKeys(s,keyB);expect((await s.evidence()).receipt).toBe(m.receipt);await setKeys(s,keyA);await denied(s.evidence());await setKeys(s,keyC,keyB);expect((await s.evidence()).receipt).toBe(m.receipt);
});
test('parallel duplicate installs commit once with one immutable expiry',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const results=await Promise.all([s.install(m),s.install(m)]);expect(results.filter(r=>!r.duplicate).length).toBe(1);expect(new Set(results.map(r=>r.expiresAt)).size).toBe(1);
});
test('same counter cannot be committed twice under parallel calls',async()=>{
 const s=stub();await setKeys(s,keyA);await s.install(material());const results=await Promise.allSettled([s.advance(1),s.advance(1)]);expect(results.filter(r=>r.status==='fulfilled'&&r.value.ok).length).toBe(1);expect((await row(s)).counter).toBe(1);
});
test('revocation erases evidence and public key, retains only finite tombstone',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);await s.revoke();expect(await row(s)).toEqual({version:1,status:'revoked',keyAddress:m.keyAddress,expiresAt:accepted.expiresAt,purgeAt:accepted.expiresAt+120000});await denied(s.evidence());await denied(s.install(m));await denied(s.rotate());
});
test('expiry at equality denies access even before alarm and purges at tombstone deadline',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);
 await clock(accepted.expiresAt,async()=>{await denied(s.evidence());expect((await row(s)).status).toBe('revoked');await denied(s.advance(1));});
 await clock(accepted.expiresAt+120000,async()=>{await runDurableObjectAlarm(s);expect(await row(s)).toBeUndefined();expect(await runInDurableObject(s,(_i,state)=>state.storage.getAlarm())).toBeNull();});
});
test('alarm expiry is idempotent and removes operation metadata first',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);await clock(m.challengeExpiresAt,async()=>{await runDurableObjectAlarm(s);expect((await row(s)).operationId).toBeUndefined();expect(await runInDurableObject(s,(_i,state)=>state.storage.getAlarm())).toBe(accepted.expiresAt);});await clock(accepted.expiresAt,async()=>{await runDurableObjectAlarm(s);expect((await row(s)).status).toBe('revoked');});
});

test('local DO restart preserves ciphertext/counter/expiry and retry result',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);const accepted=await s.install(m);await s.advance(7);const saved=await row(s);
 await abortAllDurableObjects();const reopened=namespace.get(s.id);await setKeys(reopened,keyA);expect(await row(reopened)).toEqual(saved);expect((await reopened.evidence()).counter).toBe(7);expect((await reopened.install(m)).expiresAt).toBe(accepted.expiresAt);
});
test('rotation concurrent with revoke never resurrects receipt or key',async()=>{
 const s=stub();await setKeys(s,keyA);await s.install(material());await setKeys(s,keyB,keyA);await Promise.all([s.rotate(),s.revoke()]);expect((await row(s)).status).toBe('revoked');await denied(s.evidence());expect((await row(s)).ciphertext).toBeUndefined();
});
test('first alarm failure prevents sensitive commit without client retry',async()=>{
 const s=stub();await setKeys(s,keyA);
 const outcome=await runInDurableObject(s,async(instance,state)=>{const spy=vi.spyOn(state.storage,'setAlarm').mockRejectedValueOnce(new Error('qualification_precommit_alarm_failure'));try{return await instance.install(material());}finally{spy.mockRestore();}});
 expect(outcome.ok).toBe(false);expect(await row(s)).toBeUndefined();
});
test('postcommit rearm failure retains durable trigger and cleans without client retry',async()=>{
 const s=stub(),m=material();await setKeys(s,keyA);
 const outcome=await runInDurableObject(s,async(instance,state)=>{const original=state.storage.setAlarm.bind(state.storage);let calls=0;const spy=vi.spyOn(state.storage,'setAlarm').mockImplementation((at,options)=>{calls++;if(calls===2)return Promise.reject(new Error('qualification_postcommit_alarm_failure'));return original(at,options);});try{return await instance.install(m);}finally{spy.mockRestore();}});
 expect(outcome.ok).toBe(false);const saved=await row(s);expect(saved.status).toBe('active');expect(await runInDurableObject(s,(_i,state)=>state.storage.getAlarm())).toBe(m.challengeExpiresAt);
 // No install/recover/read request is made after the failure. Only the durable alarm is executed.
 await clock(saved.expiresAt,async()=>{await runDurableObjectAlarm(s);expect((await row(s)).status).toBe('revoked');expect((await row(s)).ciphertext).toBeUndefined();});
 await clock(saved.expiresAt+120000,async()=>{await runDurableObjectAlarm(s);expect(await row(s)).toBeUndefined();});
});
test('cleanup SQL failure denies access and manual retry removes sensitive fields',async()=>{
 const s=stub();await setKeys(s,keyA);const accepted=await s.install(material());
 await clock(accepted.expiresAt,async()=>{
  const failed=await runInDurableObject(s,async(instance,state)=>{state.storage.sql.exec("CREATE TRIGGER qa_cleanup_fail BEFORE UPDATE ON key_state BEGIN SELECT RAISE(ABORT,'qualification_cleanup_failure'); END");try{await instance.alarm();return false;}catch{return true;}});
  expect(failed).toBe(true);await denied(s.evidence());await denied(s.advance(8));await runInDurableObject(s,(_i,state)=>{state.storage.sql.exec('DROP TRIGGER qa_cleanup_fail');});await runDurableObjectAlarm(s);expect((await row(s)).status).toBe('revoked');expect((await row(s)).ciphertext).toBeUndefined();
 });
});
