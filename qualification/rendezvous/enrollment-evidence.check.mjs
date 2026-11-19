import {test,expect,vi,afterEach} from 'vitest';
import fixtures from 'djc-enrollment-fixtures';
import {receiptRoot,attestationRoot} from 'djc-enrollment-trust';
import {createEnrollmentEvidenceVerifier,createSoftwareStubEnrollmentVerifier} from './enrollment-evidence-candidate.mjs';
import {qualifyAttestationCore} from './app-attest-core-candidate.mjs';
import {qualifyReceiptEvidence,qualifyFreshReceiptEvidence} from './receipt-cms-candidate.mjs';
import {CommonStatusClient} from './receipt-status-client.mjs';

const decode=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0)),time=Date.parse('2026-10-18T12:00:00Z');
const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
const point=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
const key=btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256',point))));
const id=btoa(String.fromCharCode(...new Uint8Array(32))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const denied={ok:false,error:'enrollment_rejected'};
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();});
function fixture(){
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(time);
  const state={policy:{id:'ios-dev-qualification/1',revision:'qualification-1',enabled:true,expiresAt:time+60000},challenge:{id,keyId:key,action:'register',createdAt:time-1000,expiresAt:time+119000,clientData:new TextEncoder().encode('opaque exact server-saved fixture bytes; no new wire JSON')}};
  const f={state,onStage:()=>{},request:{challengeId:id,keyId:key,attestation:new Uint8Array([1,2,3])}};
  const core={scope:'ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT',point:point.slice(),receipt:new Uint8Array([11,12]),attestedLeaf:new Uint8Array([21]),certificateExpiresAt:time+500000};
  const cms={scope:'CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT',fresh:true,created:time-1000,expires:time+500000,certificateExpiresAt:time+500000,signer:new Uint8Array([31]),issuer:new Uint8Array([41]),root:receiptRoot.slice()};
  const status=kind=>({ok:true,scope:kind==='crl'?'COMMON_RECEIPT_ISSUER_CRL_NOT_LISTED_ONLY_NO_ENROLLMENT':'COMMON_RECEIPT_OCSP_GOOD_ONLY_NO_ENROLLMENT',checkedAt:time,cacheUntil:time+30000,thisUpdate:time-1000,nextUpdate:time+120000});
  f.core=core;f.cms=cms;f.status=status;
  f.components={core:vi.fn(async(...args)=>{f.onStage('core');return core;}),cms:vi.fn(async(...args)=>{f.onStage('cms');return cms;}),status:{check:vi.fn(async(kind,...args)=>{f.onStage(kind);return status(kind);})}};
  f.verifier=()=>createSoftwareStubEnrollmentVerifier(()=>f.state,f.components);return f;
}
test('SOFTWARE_STUB_COMPOSITION success carries no enrollment or reusable authorization claim',async()=>{
  const f=fixture(),network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('forbidden'));
  const result=await f.verifier().verify(f.request);expect(result.ok).toBe(true);
  expect(result.evidence.scope).toBe('SOFTWARE_STUB_COMPOSITION_ONLY_NOT_CRYPTO_OR_ENROLLMENT_PROOF');
  expect(result.evidence.validUntil).toBe(time+30000);expect(result.evidence.publicPoint).toEqual(point);
  expect(Object.keys(result.evidence).sort()).toEqual(['scope','keyId','challengeId','challengeCreatedAt','challengeExpiresAt','policy','policyRevision','verifiedAt','validUntil','publicPoint','initialReceipt','receiptCreatedAt'].sort());
  expect(network).not.toHaveBeenCalled();
});
test('default factory rejects stub proof and never selects injected fixture functions',async()=>{
  const f=fixture(),network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('forbidden'));f.state.challenge.clientData=new Uint8Array(32);
  expect(await createEnrollmentEvidenceVerifier(()=>f.state).verify(f.request)).toEqual(denied);
  expect(f.components.core).not.toHaveBeenCalled();expect(network).not.toHaveBeenCalled();
});
for(const size of [31,33])test('default preserves exact nonce32 enrollment wire; rejects input length '+size,async()=>{
  const f=fixture();f.state.challenge.clientData=new Uint8Array(size);const digest=vi.spyOn(crypto.subtle,'digest');
  expect(await createEnrollmentEvidenceVerifier(()=>f.state).verify(f.request)).toEqual(denied);expect(digest).not.toHaveBeenCalled();
});
test('exact saved bytes and only authenticated common tuples pass between stages',async()=>{
  const f=fixture();expect((await f.verifier().verify(f.request)).ok).toBe(true);
  const a=f.components.core.mock.calls[0];expect(a[0]).toEqual(f.request.attestation);expect(a[1]).toEqual(f.state.challenge.clientData);expect(a[2]).toBe(key);expect(a[3]).toEqual(attestationRoot);
  const c=f.components.cms.mock.calls[0];expect(c).toEqual([f.core.receipt,f.core.attestedLeaf,f.state.challenge.clientData,receiptRoot]);
  expect(f.components.status.check.mock.calls).toEqual([['crl',f.cms.issuer,receiptRoot,receiptRoot],['ocsp',f.cms.signer,f.cms.issuer,receiptRoot]]);
  for(const call of f.components.status.check.mock.calls)for(const v of call.slice(1)){expect(v).not.toEqual(f.core.attestedLeaf);expect(v).not.toEqual(f.core.receipt);expect(v).not.toEqual(f.state.challenge.clientData);}
});
for(const [name,mutate] of [
 ['extra request field',f=>{f.request.status='good';}],['proof missing',f=>{f.request.attestation=undefined;}],['proof oversize',f=>{f.request.attestation=new Uint8Array(32769);}],
 ['wrong key',f=>{f.request.keyId='A'.repeat(43)+'=';}],['noncanonical key',f=>{f.request.keyId='A'.repeat(42)+'B=';}],['wrong operation',f=>{f.request.challengeId='B'.repeat(43);}],
 ['saved action',f=>{f.state.challenge.action='submit';}],['saved bytes empty',f=>{f.state.challenge.clientData=new Uint8Array();}],['saved bytes oversize',f=>{f.state.challenge.clientData=new Uint8Array(2049);}],
 ['challenge expiry equality',f=>{f.state.challenge.expiresAt=time;}],['challenge future',f=>{f.state.challenge.createdAt=time+1;}],['challenge ttl',f=>{f.state.challenge.createdAt=time-200000;}],
 ['policy disabled',f=>{f.state.policy.enabled=false;}],['policy equality',f=>{f.state.policy.expiresAt=time;}],['policy variant',f=>{f.state.policy.id='other';}],['state unknown field',f=>{f.state.user='unexpected';}],
])test('precrypto closed state/request denial: '+name,async()=>{const f=fixture();mutate(f);expect(await f.verifier().verify(f.request)).toEqual(denied);expect(f.components.core).not.toHaveBeenCalled();});
for(const [name,change] of [
 ['core failure',f=>{f.components.core.mockResolvedValue(null);}],['CMS failure',f=>{f.components.cms.mockResolvedValue(null);}],['core exception',f=>{f.components.core.mockRejectedValue(new Error('private payload never returned'));}],
 ['different point',f=>{f.core.point[1]^=1;}],['missing leaf',f=>{f.core.attestedLeaf=undefined;}],['core certificate expired',f=>{f.core.certificateExpiresAt=time;}],
 ['receipt stale',f=>{f.cms.created=time-300001;}],['receipt future',f=>{f.cms.created=time+1;}],['receipt expiry',f=>{f.cms.expires=time;}],['receipt false fresh',f=>{f.cms.fresh=false;}],
 ['CMS certificate expired',f=>{f.cms.certificateExpiresAt=time;}],['CMS wrong anchor',f=>{f.cms.root[0]^=1;}],['CMS missing signer',f=>{f.cms.signer=undefined;}],
])test('composition rejects unverified component result: '+name,async()=>{const f=fixture();change(f);expect(await f.verifier().verify(f.request)).toEqual(denied);});
for(const kind of ['crl','ocsp'])for(const [name,change] of [
 ['unavailable',s=>({...s,ok:false})],['unknown scope',s=>({...s,scope:'good'})],['expiry equality',s=>({...s,cacheUntil:time})],['future check',s=>({...s,checkedAt:time+1})],
 ['future signed update',s=>({...s,thisUpdate:time+1})],['extended cache',s=>({...s,cacheUntil:time+3600001,nextUpdate:time+7200000})],['past signed deadline',s=>({...s,cacheUntil:time+1,nextUpdate:time})],
])test('hard-fail exact status '+kind+': '+name,async()=>{const f=fixture();f.components.status.check.mockImplementation(async k=>k===kind?change(f.status(k)):f.status(k));expect(await f.verifier().verify(f.request)).toEqual(denied);});
for(const stage of ['core','cms','crl','ocsp'])for(const [name,change] of [
 ['revoke policy',f=>{f.state.policy.enabled=false;}],['new policy revision',f=>{f.state.policy.revision='qualification-2';}],['saved bytes replaced',f=>{f.state.challenge.clientData[0]^=1;}],
 ['key replaced',f=>{f.state.challenge.keyId='A'.repeat(43)+'=';}],['expiry changed',f=>{f.state.challenge.expiresAt--;}],['original deadline passed',f=>{vi.setSystemTime(time+119000);}],
])test('current authority rechecked after '+stage+': '+name,async()=>{const f=fixture();f.onStage=s=>{if(s===stage)change(f);};expect(await f.verifier().verify(f.request)).toEqual(denied);});
test('policy change during point digest is denied before CMS',async()=>{
  const f=fixture(),digest=crypto.subtle.digest.bind(crypto.subtle);vi.spyOn(crypto.subtle,'digest').mockImplementation(async(...a)=>{const v=await digest(...a);f.state.policy.enabled=false;return v;});
  expect(await f.verifier().verify(f.request)).toEqual(denied);expect(f.components.cms).not.toHaveBeenCalled();
});
for(const field of ['issuer status','attestation certificate','CMS certificate','receipt expiry','receipt freshness'])test('evidence cannot expire during later status: '+field,async()=>{
  const f=fixture();let cutoff=time+1;
  if(field==='attestation certificate')f.core.certificateExpiresAt=cutoff;
  if(field==='CMS certificate')f.cms.certificateExpiresAt=cutoff;
  if(field==='receipt expiry')f.cms.expires=cutoff;
  if(field==='receipt freshness'){f.cms.created=time-300000;cutoff=time+1;}
  f.components.status.check.mockImplementation(async kind=>{const s=f.status(kind);if(kind==='crl'&&field==='issuer status')s.cacheUntil=cutoff;if(kind==='ocsp')vi.setSystemTime(cutoff);return s;});
  expect(await f.verifier().verify(f.request)).toEqual(denied);
});
test('receipt freshness at exactly five minutes remains the existing inclusive millisecond policy',async()=>{
  const f=fixture();f.cms.created=time-300000;const result=await f.verifier().verify(f.request);expect(result.ok).toBe(true);expect(result.evidence.validUntil).toBe(time+1);
});
for(const kind of ['Uint8Array','Buffer'])test('request bytes copied before async work, including view-style Buffer slices: '+kind,async()=>{
  const f=fixture();if(kind==='Buffer'){f.request.attestation=Buffer.from(f.request.attestation);f.state.challenge.clientData=Buffer.from(f.state.challenge.clientData);}let release;const gate=new Promise(r=>{release=r;});
  f.components.core.mockImplementation(async(proof,input)=>{await gate;expect(proof).toEqual(new Uint8Array([1,2,3]));input.fill(0);return f.core;});
  const pending=f.verifier().verify(f.request);f.request.attestation.fill(9);release();expect((await pending).ok).toBe(true);expect(f.state.challenge.clientData[0]).not.toBe(0);
});
test('one active verifier call; concurrent proof denied and exception releases busy guard',async()=>{
  const f=fixture(),v=f.verifier();let release;const gate=new Promise(r=>{release=r;});
  f.components.core.mockImplementationOnce(async()=>{await gate;throw new Error('private');});const first=v.verify(f.request);
  expect(await v.verify(f.request)).toEqual(denied);release();expect(await first).toEqual(denied);expect((await v.verify(f.request)).ok).toBe(true);
});
test('component result aliases cannot renew a prior receipt/status decision',async()=>{
  const f=fixture(),prior=f.status('crl');prior.cacheUntil=time+1;
  f.components.status.check.mockImplementation(async kind=>{if(kind==='crl')return prior;vi.setSystemTime(time+1);prior.cacheUntil=time+10000;f.cms.created=time+1;return f.status(kind);});
  expect(await f.verifier().verify(f.request)).toEqual(denied);
});
for(const [field,delta] of [['policy',10000],['challenge',15000],['attestation',20000],['CMS',25000]])test('private evidence deadline capped by '+field,async()=>{
  const f=fixture();if(field==='policy')f.state.policy.expiresAt=time+delta;if(field==='challenge')f.state.challenge.expiresAt=time+delta;if(field==='attestation')f.core.certificateExpiresAt=time+delta;if(field==='CMS')f.cms.certificateExpiresAt=time+delta;
  const result=await f.verifier().verify(f.request);expect(result.ok).toBe(true);expect(result.evidence.validUntil).toBe(time+delta);
});
for(const f of fixtures.genuine){
  test('genuine archived core metadata uses authenticated leaf/path deadline: '+f.name,async()=>{
    const result=await qualifyAttestationCore(decode(f.attestation),decode(f.input),f.credential,attestationRoot);
    expect(Array.from(result?.attestedLeaf??[])).toEqual(Array.from(decode(f.leaf)));expect(result.certificateExpiresAt).toBe(f.pathExpiresAt);
  });
  test('genuine archived CMS exposes common tuple but remains stale: '+f.name,async()=>{
    const result=await qualifyReceiptEvidence(decode(f.receipt),decode(f.leaf),decode(f.input),receiptRoot);
    expect(result?.root).toEqual(receiptRoot);expect(result.signer).not.toEqual(decode(f.leaf));expect(result.issuer).not.toEqual(decode(f.leaf));expect(result.certificateExpiresAt).toBe(f.cmsExpiresAt);expect(result.fresh).toBe(false);
    expect(await qualifyFreshReceiptEvidence(decode(f.receipt),decode(f.leaf),decode(f.input),receiptRoot)).toBeNull();
  });
  test('default nonce32 adapter denies archived diagnostic input shape without status fetch: '+f.name,async()=>{
    const now=Date.now(),state={policy:{id:'ios-dev-qualification/1',revision:'qualification-1',enabled:true,expiresAt:now+120000},challenge:{id,keyId:f.credential,action:'register',createdAt:now,expiresAt:now+120000,clientData:decode(f.input)}};
    const network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('no external request'));
    expect(await createEnrollmentEvidenceVerifier(()=>state).verify({challengeId:id,keyId:f.credential,attestation:decode(f.attestation)})).toEqual(denied);expect(network).not.toHaveBeenCalled();
  });
  test('real core and CMS composed through explicit fixture path deny stale receipt before status: '+f.name,async()=>{
    const now=Date.now(),state={policy:{id:'ios-dev-qualification/1',revision:'qualification-1',enabled:true,expiresAt:now+120000},challenge:{id,keyId:f.credential,action:'register',createdAt:now,expiresAt:now+120000,clientData:decode(f.input)}};
    const network=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('no external request')),cms=vi.fn(qualifyFreshReceiptEvidence),status=new CommonStatusClient(),check=vi.spyOn(status,'check');
    const verifier=createSoftwareStubEnrollmentVerifier(()=>state,{core:qualifyAttestationCore,cms,status});
    expect(await verifier.verify({challengeId:id,keyId:f.credential,attestation:decode(f.attestation)})).toEqual(denied);expect(cms).toHaveBeenCalledOnce();expect(check).not.toHaveBeenCalled();expect(network).not.toHaveBeenCalled();
  });
}

// A saved-state callback belongs to the coordinator, not to proof evaluation.
for(const at of [1,2,3,4,5,6,7,8])for(const name of ['Error','null','string','lookalike'])test('saved-state callback fault preserves identity and releases busy: '+name+' read'+at,async()=>{
 const f=fixture();let reads=0,hits=0;
 const marker=name==='Error'?new Error('enrollment_rejected private marker'):name==='null'?null:name==='string'?'attestation_unavailable':{name:'RegistrationRejected',message:'enrollment_rejected'};
 const verifier=createSoftwareStubEnrollmentVerifier(()=>{reads++;if(reads===at){hits++;throw marker;}return f.state;},f.components);
 await expect(verifier.verify(f.request)).rejects.toBe(marker);expect(hits).toBe(1);
 expect((await verifier.verify(f.request)).ok).toBe(true);
});

// Only the fixed, validated post-core public-point digest is under this fault boundary.
for(const kind of ['Error','DOMException','lookalike','undefined'])test('fixed enrollment point digest preserves original cause and releases busy: '+kind,async()=>{
 const f=fixture(),v=f.verifier(),cause=kind==='Error'?new Error('enrollment_rejected attestation_unavailable PRIVATE'):kind==='DOMException'?new DOMException('PRIVATE','DataError'):kind==='lookalike'?{name:'StateReadFailure',message:'enrollment_rejected'}:undefined;
 const before=structuredClone(f.state),original=crypto.subtle.digest.bind(crypto.subtle);let hits=0,inject=true;
 const spy=vi.spyOn(crypto.subtle,'digest').mockImplementation(async(...args)=>{if(inject&&args[0]==='SHA-256'&&Buffer.from(args[1]).equals(Buffer.from(point))){hits++;throw cause;}return original(...args);});
 try{await expect(v.verify(f.request)).rejects.toBe(cause);expect(hits).toBe(1);expect(f.components.core).toHaveBeenCalledOnce();expect(f.components.cms).not.toHaveBeenCalled();expect(f.components.status.check).not.toHaveBeenCalled();expect(f.state).toEqual(before);
  inject=false;const repaired=await v.verify(f.request);expect(repaired.ok).toBe(true);expect(repaired.evidence.validUntil).toBe(time+30000);expect(f.state).toEqual(before);
 }finally{spy.mockRestore();}
});
test('healthy wrong enrollment point digest remains an ordinary proof rejection',async()=>{
 const f=fixture(),spy=vi.spyOn(crypto.subtle,'digest').mockResolvedValue(new Uint8Array(32).buffer);
 try{expect(await f.verifier().verify(f.request)).toEqual(denied);expect(spy).toHaveBeenCalledOnce();expect(f.components.cms).not.toHaveBeenCalled();}finally{spy.mockRestore();}
});
for(const size of [64,66])test('invalid post-core point shape rejects before fixed digest: '+size,async()=>{
 const f=fixture();f.core.point=new Uint8Array(size);const spy=vi.spyOn(crypto.subtle,'digest');
 try{expect(await f.verifier().verify(f.request)).toEqual(denied);expect(spy).not.toHaveBeenCalled();expect(f.components.cms).not.toHaveBeenCalled();}finally{spy.mockRestore();}
});
