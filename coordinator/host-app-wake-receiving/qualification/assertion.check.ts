import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,it,expect,vi} from 'vitest';
import cbor from 'cbor';import * as pki from 'pkijs';
import firstJobGuard from '../native-first-job-guard.sql?raw';
import keyInsertGuard from '../native-key-insert-guard.sql?raw';
import firstProofGuard from '../native-first-proof-guard.sql?raw';
import issuerGuard from '../issuer-guard.sql?raw';
import schema from '../schema.sql?raw';import eligibility from '../eligibility-view.sql?raw';import regGuard from '../registration-guard.sql?raw';import dispatchGuard from '../dispatch-guard.sql?raw';import hostSchema from '../../host-app-wake/schema.sql?raw';import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import {TARGET_CAPABILITY_HEADER,TARGET_OPERATION_HEADER,TARGET_REQUEST_HASH_HEADER,decodeTargetReply} from '../target-transport';
import {createReceivingService} from '../service';
import {decodeNativePolicy,assertionPolicyForNative,OPERATOR_NATIVE_POLICY} from '../native-policy';
import {resolveAuthorization,decodeResolvedAuthorization,RESOLVE_PATH} from '../authorization-resolve';
import {sha256Hex} from '../../../src/crypto';
import {bindSource181} from '../source-backend';
import type {AppEnv} from '../../../src/types';
import {WakeStore} from '../../host-app-wake/store';
import {VERSION as SOURCE_VERSION,PREFIX} from '../../host-app-wake/wire';
import {ReceivingStore} from '../receiving-store';import {RequestWindow} from '../request-window';
import {verifySavedAssertion,commitVerifiedAssertion} from '../native-assertion';
import {canonical} from '../../../src/surface-push/wire';
import {decodeNativeOriginal,decodeOperatorAuthorization,nativeSigningData,RECEIVING_VERSION,OPERATOR_AUTHORIZE} from '../wire';
import vectors from './native-transcript-vectors.json';
// All native key/policy/Apple issuer authority here is SYNTHETIC. Actual
// WebCrypto ECDSA and D1 counter CAS are reached; NO genuine enrollment/device.
let at:number,store:ReceivingStore,pair:CryptoKeyPair,sourceEnv:AppEnv,capabilities:Map<string,string>,o:ReturnType<typeof decodeNativeOriginal>,spki:string;
const app='ABCDEFGHIJ.example.fixture.host',claim='original-native-claim';
const b64=(b:Uint8Array)=>btoa(String.fromCharCode(...b));
const hash=async(b:Uint8Array)=>new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(b)));
function combine(a:Uint8Array,b:Uint8Array){const c=new Uint8Array(a.length+b.length);c.set(a);c.set(b,a.length);return c;}
function clock(){return new RequestWindow(()=>Date.now(),new AbortController().signal);}
async function job(original=o,id=vectors.challenge.challenge_id,nonce='A'.repeat(43),privateClaim=claim){
 const c={challenge_id:id,nonce_b64url:nonce,captured_at_ms:at,expires_at_ms:at+30000};
 await store.reserveIssuer('authorization','record','issuer-'+original.core_purpose_id,'b'.repeat(64),original,'private-'+original.core_purpose_id,'issuer-claim',at,at,'app_attest_assertion');
 const issuer=(await store.issuer('authorization',original.core_purpose_id))!,w=clock(),backend=await bindSource181(sourceEnv,issuer,'record',w,async()=>new Response('not-used'),16);
 try{const issued=await backend.service.issueOriginal(undefined,w.signal);capabilities.set(original.core_purpose_id,issued.credential);}finally{backend.close();w.close();}
 await store.finishIssuer('authorization',original.core_purpose_id,'issued',Date.now(),'issuer-claim','b'.repeat(64),'record');
 await store.reserveNativeJob('authorization','record',original,c,'c'.repeat(64),'app_attest_assertion',Date.now());
 expect(await store.claimNativeProof('authorization','record',id,'app_attest_assertion',privateClaim,Date.now())).toBe(true);return c;
}
async function assertion(original=o,challenge=vectors.challenge,counter=1){
 const props=cbor.encode(new Map<string,unknown>([['apple_bundle_version_01','12345'],['apple_validation_category_01',Buffer.from([3,0,0,0])]]));
 const auth=new Uint8Array(37+props.length);auth.set(await hash(new TextEncoder().encode(app)));auth[32]=0xc0;new DataView(auth.buffer).setUint32(33,counter,false);auth.set(props,37);
 const data=nativeSigningData(original,challenge).client_data;const nonce=await hash(combine(auth,await hash(data)));
 const raw=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,nonce));const der=new Uint8Array(pki.createCMSECDSASignature(raw.buffer));
 return {kind:'app_attest_assertion' as const,bytes_b64:b64(cbor.encode(new Map([['signature',Buffer.from(der)],['authenticatorData',Buffer.from(auth)]])))};
}
let c:{challenge_id:string;nonce_b64url:string;captured_at_ms:number;expires_at_ms:number};
describe('actual saved-key assertion crypto + atomic D1 counter receipt, SYNTHETIC authority only',()=>{
 beforeAll(async()=>{for(const text of [installSchema,hostSchema,schema])for(const sql of text.replace(/--[^\n]*/g,'').split(';').filter(x=>x.trim()))await env.DB.prepare(sql).run();for(const sql of [eligibility,regGuard,dispatchGuard,issuerGuard,firstJobGuard,keyInsertGuard,firstProofGuard])await env.DB.prepare(sql).run();});
 beforeEach(async()=>{
  for(const table of ['host_wake_native_pending_policies','host_wake_child_withdrawals','host_wake_receiving_intents','host_wake_native_verifications','host_wake_native_enrollments','host_wake_native_jobs','host_wake_issuer_once','host_wake_operator_authorizations','host_app_wake_operations','host_app_wake_purposes','install_tokens'])await env.DB.prepare('DELETE FROM '+table).run();
  capabilities=new Map();sourceEnv={...env,APNS_TEAM_ID:'ABCDEFGHIJ',APNS_KEY_ID:'KLMNOPQRST',APNS_PRIVATE_KEY:'synthetic-unused-provider-key-not-a-real-credential',APNS_TOPIC_IOS:'example.fixture.host',APNS_ENVIRONMENT:'sandbox',APNS_TOKEN_ENCRYPTION_KEY:btoa('0123456789abcdef0123456789abcdef')} as AppEnv;
  at=Date.now()-100;store=new ReceivingStore(env.DB,16);pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;
  const point=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey) as ArrayBuffer);spki=b64(new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey) as ArrayBuffer));
  o=decodeNativeOriginal({...vectors.original,native_key_id_b64:b64(await hash(point)),original_wake_issued_at_ms:at,original_wake_expires_at_ms:at+3600000,original_display_expires_at_ms:at+7200000});
  const {native_key_id_b64,native_token_sha256,core_purpose_id,operation_id,generation,revision,token_role,original_wake_issued_at_ms,original_wake_expires_at_ms,original_display_expires_at_ms,version,...scope}=o;
  await env.DB.prepare("INSERT INTO install_tokens(id,ha_install_id,token_hash,token_prefix) VALUES ('record','install',?,'djci_fixture')").bind(await sha256Hex('djci_'+'A'.repeat(43))).run();
  await store.authorize(decodeOperatorAuthorization({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',operation_id:'operator-op',authorization_id:'authorization',core_install_token_record_id:'record',ha_install_id:'install',native_key_ref:'native-record',...scope,max_original_purpose_ms:28800000,max_operations:256,max_reserved_sends:64,original_authorization_issued_at_ms:at-1,original_authorization_expires_at_ms:at+7200000}),'a'.repeat(64),at,at);
  await env.DB.prepare(`INSERT INTO host_wake_native_enrollments(native_key_ref,native_key_id_b64,public_key_spki_b64,assertion_policy_json,host_bundle,install_id,platform,environment,identity_policy_sha256,deployment_policy_sha256,enrollment_receipt_sha256,signed_environment_receipt_sha256,issued_at,expires_at,counter) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`)
   .bind('native-record',o.native_key_id_b64,spki,canonical({profile:'host_wake_apple_assertion_properties_v1',app_identifier:app,bundle_version:'12345'}),o.target.host_bundle_id,o.target.installation_id,o.platform,o.apns_environment,o.identity_policy_sha256,o.deployment_policy_sha256,'e'.repeat(64),'f'.repeat(64),at,at+7200000).run();
  // Trusted SYNTHETIC prior-enrollment fixture, not a first-Apple verifier
  // result or production seed. The HTTP backend now requires a bound v2 policy;
  // old unbound/QA rows cannot become native authority through API composition.
  const nativePolicy=decodeNativePolicy({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_NATIVE_POLICY,action:'native_policy',operation_id:'synthetic-prior-policy',authorization_id:'authorization',native_key_ref:'native-record',native_key_id_b64:o.native_key_id_b64,profile:'host_wake_apple_properties_attestation_v2',app_identifier:app,apns_team_id:'ABCDEFGHIJ',app_attest_environment:'development',bundle_version:'12345',launch_validation_category_b64:btoa(String.fromCharCode(3,0,0,0)),signed_host_artifact_sha256:'9'.repeat(64),signed_environment_receipt_sha256:'f'.repeat(64),scope,original_policy_issued_at_ms:at,original_policy_expires_at_ms:at+7200000});
  await env.DB.prepare(`INSERT INTO host_wake_native_pending_policies(native_key_ref,native_key_id_b64,authorization_id,operation_id,request_hash,policy_json,issued_at,expires_at,outcome,original_request_expires_at) VALUES(?,?,?,?,?,?,?,?,'enrolled',?)`).bind('native-record',o.native_key_id_b64,'authorization',nativePolicy.operation_id,'9'.repeat(64),canonical(nativePolicy),at,at+7200000,at+30000).run();
  await env.DB.prepare('UPDATE host_wake_native_enrollments SET native_policy_json=?,assertion_policy_json=?').bind(canonical(nativePolicy),assertionPolicyForNative(nativePolicy)).run();
  c=await job();
 });
 async function verified(w:RequestWindow){return verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,claim,await assertion(o,c),w);}
 it('verifies actual ECDSA bytes then commits one atomic actual counter/proof receipt with no caller key/boolean',async()=>{
  const w=clock();try{const result=await verified(w);expect(result).not.toBeNull();expect(await commitVerifiedAssertion(result!,w)).toBe(true);expect(await env.DB.prepare('SELECT counter FROM host_wake_native_enrollments').first('counter')).toBe(1);expect((await store.nativeJob(c.challenge_id))?.outcome).toBe('verified');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(1);}finally{w.close();}
 });
 it('cannot manufacture a branded crypto receipt from JSON or replay an actual one',async()=>{
  const w=clock();try{await expect(commitVerifiedAssertion({kind:'host_wake_assertion_crypto_only'},w)).rejects.toThrow('host_wake_native_crypto_receipt_required');const result=await verified(w);expect(await commitVerifiedAssertion(result!,w)).toBe(true);await expect(commitVerifiedAssertion(result!,w)).rejects.toThrow('host_wake_native_crypto_receipt_required');}finally{w.close();}
 });
 it('does not let a second crypto receipt claim another concurrent counter winner result',async()=>{
  const w=clock();try{const a=await verified(w),b=await verified(w);const results=await Promise.all([commitVerifiedAssertion(a!,w),commitVerifiedAssertion(b!,w)]);expect(results.filter(Boolean)).toHaveLength(1);}finally{w.close();}
 });
 it('binds actual proof to the original saved nonce and full frozen transcript',async()=>{
  const input=await assertion(o,c);await env.DB.prepare('UPDATE host_wake_native_jobs SET challenge_json=?').bind(canonical({...c,nonce_b64url:'B'+'A'.repeat(42)})).run();const w=clock();try{expect(await verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,claim,input,w)).toBeNull();}finally{w.close();}
 });
 it('rejects an actual stale/replayed native counter',async()=>{
  await env.DB.prepare('UPDATE host_wake_native_enrollments SET counter=1').run();const w=clock();try{expect(await verified(w)).toBeNull();}finally{w.close();}
 });
 it.each([
  "UPDATE install_tokens SET disabled=1",
  "UPDATE host_wake_operator_authorizations SET outcome='withdrawn'",
  "UPDATE host_wake_native_enrollments SET disabled=1",
  "UPDATE host_wake_native_enrollments SET environment='production'",
  "UPDATE host_wake_native_enrollments SET deployment_policy_sha256='changed'",
  "UPDATE host_wake_native_enrollments SET public_key_spki_b64='changed'",
  "UPDATE host_wake_native_jobs SET outcome='unknown'",
  "UPDATE host_wake_native_jobs SET expires_at=captured_at",
 ])('cannot commit a positive native receipt after actual local state changes: %s',async sql=>{
  const w=clock();try{const result=await verified(w);expect(result).not.toBeNull();await env.DB.prepare(sql).run();expect(await commitVerifiedAssertion(result!,w)).toBe(false);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(0);}finally{w.close();}
 });
 it('never adopts an absent or old fixed-QA policy as a host-native policy',async()=>{
  await env.DB.prepare('UPDATE host_wake_native_enrollments SET assertion_policy_json=NULL').run();const w=clock();try{await expect(verified(w)).rejects.toThrow('host_wake_native_policy_unavailable');}finally{w.close();}
 });
 it('preserves original WebCrypto verify exceptions rather than reporting invalid proof',async()=>{
  const input=await assertion(o,c),error=new Error('synthetic fixed-operation WebCrypto failure'),spy=vi.spyOn(crypto.subtle,'verify').mockRejectedValueOnce(error);const w=clock();try{await expect(verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,claim,input,w)).rejects.toBe(error);}finally{spy.mockRestore();w.close();}
 });
 it('refuses attestation-to-assertion fallback and another private job claim',async()=>{
  const w=clock();try{await expect(verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,claim,{kind:'app_attest_attestation',bytes_b64:'AA=='},w)).rejects.toThrow('host_wake_native_attestation_unavailable');await expect(verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,'not-the-original-claim',await assertion(o,c),w)).rejects.toThrow('host_wake_native_job_consumed');}finally{w.close();}
 });
 it('serializes competing genuine-synthetic signatures at the actual one-key counter CAS across different original jobs',async()=>{
  const o2=decodeNativeOriginal({...o,core_purpose_id:'second-original-purpose',operation_id:'33333333-3333-4333-8333-333333333333'}),claim2='second-native-claim';const c2=await job(o2,'44444444-4444-4444-8444-444444444444','B'+'A'.repeat(42),claim2);const w=clock();
  try{const a=await verified(w),b=await verifySavedAssertion(env.DB,'authorization','record',c2.challenge_id,claim2,await assertion(o2,c2),w);expect(a).not.toBeNull();expect(b).not.toBeNull();const results=await Promise.all([commitVerifiedAssertion(a!,w),commitVerifiedAssertion(b!,w)]);expect(results.filter(Boolean)).toHaveLength(1);expect(await env.DB.prepare('SELECT counter FROM host_wake_native_enrollments').first('counter')).toBe(1);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(1);}finally{w.close();}
 });
 it.each(['digest','importKey'] as const)('preserves a fixed trusted WebCrypto %s failure as the original cause',async method=>{
  const input=await assertion(o,c),error=new Error('synthetic-fixed-'+method),spy=vi.spyOn(crypto.subtle,method).mockRejectedValueOnce(error);const w=clock();try{await expect(verifySavedAssertion(env.DB,'authorization','record',c.challenge_id,claim,input,w)).rejects.toBe(error);}finally{spy.mockRestore();w.close();}
 });

 async function targetRegister(token=vectors.native_token_hex,operation=o.operation_id){
  const w=clock(),issuer=(await store.issuer('authorization',o.core_purpose_id))!,backend=await bindSource181(sourceEnv,issuer,'record',w,async()=>new Response('not-used'),16);
  try{return await backend.service.handle(new Request('https://local.test'+PREFIX+'register',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+capabilities.get(o.core_purpose_id)},body:JSON.stringify({version:SOURCE_VERSION,purpose_id:issuer.private_purpose_id,operation_id:operation,generation:o.generation,revision:o.revision,token_role:'host_app_wake' as const,target:o.target,apns_environment:o.apns_environment,apns_token:token}),signal:w.signal}));}finally{backend.close();w.close();}
 }
 it('binds actual Source181 issue and register to the verified original native bytes and consumes proof in the same D1 ACK',async()=>{
  const w=clock();try{const result=await verified(w);expect(await commitVerifiedAssertion(result!,w)).toBe(true);}finally{w.close();}
  const r=await targetRegister();expect(r.status).toBe(200);expect(await r.json()).toMatchObject({operation_state:'registered'});
  const proof=await env.DB.prepare('SELECT consumed_at,register_operation_id FROM host_wake_native_verifications').first<{consumed_at:number;register_operation_id:string}>();expect(proof!.consumed_at).toBeGreaterThan(0);expect(proof!.register_operation_id).toBe(o.operation_id);
  const saved=await env.DB.prepare('SELECT ciphertext FROM host_app_wake_purposes WHERE purpose_id=?').bind('private-'+o.core_purpose_id).first<{ciphertext:string}>();expect(saved!.ciphertext).not.toContain(vectors.native_token_hex);
 });
 it('does not substitute a structurally valid different native token or a different semantic registration',async()=>{
  const w=clock();try{expect(await commitVerifiedAssertion((await verified(w))!,w)).toBe(true);}finally{w.close();}
  expect((await targetRegister('ff'.repeat(32))).status).toBe(403);expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT withdrawn FROM host_app_wake_purposes WHERE purpose_id=?').bind('private-'+o.core_purpose_id).first('withdrawn')).toBe(1);
  expect(await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at')).toBeNull();
 });
 it('retains one actual durable Source181 ACK on same-operation status replay without another proof consumption',async()=>{
  const w=clock();try{expect(await commitVerifiedAssertion((await verified(w))!,w)).toBe(true);}finally{w.close();}
  expect((await targetRegister()).status).toBe(200);const first=await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at');expect((await targetRegister()).status).toBe(200);expect(await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at')).toBe(first);expect(await env.DB.prepare("SELECT COUNT(*) n FROM host_app_wake_operations WHERE kind='register'").first('n')).toBe(1);
 });

 it.each(['APNS_ENVIRONMENT','APNS_TOPIC_IOS','APNS_TEAM_ID'] as const)('does not select a positive source backend with actual configuration %s mismatch',async field=>{
  const bad={...sourceEnv,[field]:'not-the-selected-value'},w=clock();try{await expect(bindSource181(bad,(await store.issuer('authorization',o.core_purpose_id))!,'record',w,async()=>new Response('not-used'),16)).rejects.toThrow('host_wake_native_deployment_mismatch');}finally{w.close();}
 });
 it('terminally withdraws this child on unsupported semantic registration replacement without minting another purpose',async()=>{
  const w=clock();try{expect(await commitVerifiedAssertion((await verified(w))!,w)).toBe(true);}finally{w.close();}
  expect((await targetRegister(vectors.native_token_hex,'another-register-operation')).status).toBe(403);expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_app_wake_purposes').first('n')).toBe(1);
 });

 function resolveRequest(extra:Record<string,unknown>={}){
  const {native_key_id_b64,paired_subject_binding_sha256,owner_binding,device_binding,source_binding,target,platform,apns_environment}=o;
  return new Request('https://local.test'+RESOLVE_PATH,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer djci_'+'A'.repeat(43)},body:JSON.stringify({version:RECEIVING_VERSION,scope:{native_key_id_b64,paired_subject_binding_sha256,owner_binding,device_binding,source_binding,target,platform,apns_environment,...extra}})});
 }
 it('resolves only the existing exact operator/native role, without any semantic intent, credential or new row',async()=>{
  const before=await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_operator_authorizations').first('n');const result=await resolveAuthorization(resolveRequest(),sourceEnv,()=>Date.now());
  expect(decodeResolvedAuthorization(result.request_sha256,result.scope_sha256,result)).toEqual(result);expect(()=>decodeResolvedAuthorization(result.request_sha256,result.scope_sha256,{...result,credential:'not-returned'})).toThrow();expect(()=>decodeResolvedAuthorization('f'.repeat(64),result.scope_sha256,result)).toThrow();expect(result.authorization_id).toBe('authorization');expect(result.registration_mode).toBe('single_original_no_rotation');expect(result.native_proof_kind).toBe('app_attest_assertion');expect(result.original_authorization_expires_at_ms).toBe(at+7200000);
  expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_operator_authorizations').first('n')).toBe(before);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n')).toBe(0);
  for(const field of ['credential','purpose_id','private_job_id','proof','transcript','token','private_key'])expect(Object.hasOwn(result,field)).toBe(false);
 });
 it.each(['owner_binding','device_binding','source_binding','paired_subject_binding_sha256'])('does not discover a different actual scope %s',async field=>{await expect(resolveAuthorization(resolveRequest({[field]:'f'.repeat(64)}),sourceEnv,()=>Date.now())).rejects.toThrow('host_wake_authorization_unavailable');});
 it.each(['selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256'])('rejects a caller supplied policy/origin hash %s',async field=>{await expect(resolveAuthorization(resolveRequest({[field]:'f'.repeat(64)}),sourceEnv,()=>Date.now())).rejects.toThrow();});
 it('returns existing role policy hashes and refuses ambiguity even across different origins or policies',async()=>{
  const result=await resolveAuthorization(resolveRequest(),sourceEnv,()=>Date.now());
  expect(result.selected_ha_origin_sha256).toBe(o.selected_ha_origin_sha256);expect(result.identity_policy_sha256).toBe(o.identity_policy_sha256);expect(result.deployment_policy_sha256).toBe(o.deployment_policy_sha256);
  const saved=(await store.authorization('authorization'))!,data=decodeOperatorAuthorization(JSON.parse(saved.authorization_json));
  await store.authorize({...data,authorization_id:'different-origin-role',operation_id:'different-origin-operation',selected_ha_origin_sha256:'9'.repeat(64)},'d'.repeat(64),Date.now(),Date.now());
  await expect(resolveAuthorization(resolveRequest(),sourceEnv,()=>Date.now())).rejects.toThrow('host_wake_authorization_unavailable');
 });
 it('does not pick a latest grant, create a replacement or expose a role after retirement',async()=>{
  const saved=(await store.authorization('authorization'))!,data=decodeOperatorAuthorization(JSON.parse(saved.authorization_json));await store.authorize({...data,authorization_id:'second-authorization',operation_id:'second-operator-operation'},'d'.repeat(64),Date.now(),Date.now());await expect(resolveAuthorization(resolveRequest(),sourceEnv,()=>Date.now())).rejects.toThrow('host_wake_authorization_unavailable');
  await store.withdrawAuthorization('second-authorization');await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();await expect(resolveAuthorization(resolveRequest(),sourceEnv,()=>Date.now())).rejects.toThrow('host_wake_core_auth');
 });

 function privateRequest(route:string,value:Record<string,unknown>,overrides:Record<string,string>={}){
  return new Request('https://local.test/v1/push/host-app-wake/'+route,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer djci_'+'A'.repeat(43),'x-djconnect-host-wake-authorization-id':'authorization','x-djconnect-host-wake-core-purpose-id':String(value.core_purpose_id),'x-djconnect-host-wake-issuer-operation-id':String(value.issuer_operation_id),...overrides},body:JSON.stringify(value)});
 }
 const serverInput=(purpose=o.core_purpose_id)=>({version:RECEIVING_VERSION,authorization_id:'authorization',core_purpose_id:purpose,issuer_operation_id:'issuer-'+purpose});
 function receiving(config=sourceEnv,capacity=16){return createReceivingService({env:config,capacity,now:()=>Date.now(),fetcher:async()=>{throw Error('NO PROVIDER EFFECT PERMITTED IN HTTP QUALIFICATION');}});}
 it('runs actual issuer/challenge/complete/status HTTP with real ECDSA and atomic counter, no provider or fixture-verdict callback',async()=>{
  const svc=receiving(),original=decodeNativeOriginal({...o,core_purpose_id:'http-child',operation_id:'33333333-3333-4333-8333-333333333333'}),input=serverInput(original.core_purpose_id);
  try{
   const issue=await svc.handle(privateRequest('issuer/issue',{...input,original}));expect(issue.status).toBe(200);const issued=await issue.json() as Record<string,unknown>;expect(issued.credential_state).toBe('available');expect(issued.credential).toMatch(/^djchw_/);
   const request={...input,challenge_id:'55555555-5555-4555-8555-555555555555'};
   const challenge=await svc.handle(privateRequest('native/challenge',request));expect(challenge.status).toBe(200);const native=await challenge.json() as Record<string,unknown>;
   const proof=await assertion(original,native.challenge as typeof c);
   const complete=await svc.handle(privateRequest('native/complete',{...request,native_proof:proof}));expect(complete.status).toBe(200);expect((await complete.json() as Record<string,unknown>).state).toBe('native_verified');
   const status=await svc.handle(privateRequest('native/status',request));expect(status.status).toBe(200);const out=await status.json() as Record<string,unknown>;expect(out.state).toBe('native_verified');expect(Object.hasOwn(out,'credential')).toBe(false);
   expect(await env.DB.prepare('SELECT counter FROM host_wake_native_enrollments').first('counter')).toBe(1);expect((await store.nativeJob(request.challenge_id))?.outcome).toBe('verified');
   const retry=await svc.handle(privateRequest('issuer/issue',{...input,original}));expect(retry.status).toBe(409);expect((await store.issuer('authorization',original.core_purpose_id))?.outcome).toBe('issued');
  }finally{svc.close();}
 });
 it('never lets an existing issuer loser close the winning private reserved claim',async()=>{
  const original=decodeNativeOriginal({...o,core_purpose_id:'reserved-http-child'}),input=serverInput(original.core_purpose_id);
  const hash=await sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST','/v1/push/host-app-wake/issuer/issue',{...input,original}]));
  await store.reserveIssuer('authorization','record',input.issuer_operation_id,hash,original,'existing-private-child','retained-winning-claim',at,at,'app_attest_assertion');
  const svc=receiving();try{const reply=await svc.handle(privateRequest('issuer/issue',{...input,original}));expect(reply.status).toBe(409);expect((await store.issuer('authorization',original.core_purpose_id))?.outcome).toBe('reserved');}finally{svc.close();}
 });
 it('closes a real child at full capacity without capability, encryption or provider configuration',async()=>{
  const svc=receiving({...env} as AppEnv,1);try{
   const result=await svc.handle(privateRequest('issuer/withdraw',serverInput()));expect(result.status).toBe(200);const body=await result.json() as Record<string,unknown>;expect(body.state).toBe('withdrawn');expect(Object.hasOwn(body,'credential')).toBe(false);
   expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n')).toBe(0);
  }finally{svc.close();}
 });
 it('retains an early negative child fence before late issuer/body allocation, even for a changed transport operation',async()=>{
  const purpose='early-withdrawn',svc=receiving();try{
   expect((await svc.handle(privateRequest('issuer/withdraw',serverInput(purpose)))).status).toBe(404);
   const original={...o,core_purpose_id:purpose};const result=await svc.handle(privateRequest('issuer/issue',{...serverInput(purpose),issuer_operation_id:'changed-issuer-operation',original}));expect(result.status).toBe(409);expect(await store.issuer('authorization',purpose)).toBeNull();expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n')).toBe(0);
  }finally{svc.close();}
 });
 it('does not acknowledge unknown child closure when its bounded fence capacity is exhausted',async()=>{
  const svc=receiving(sourceEnv,1);try{
   expect((await svc.handle(privateRequest('issuer/withdraw',serverInput('first-early-child')))).status).toBe(404);
   expect((await svc.handle(privateRequest('issuer/withdraw',serverInput('second-early-child')))).status).toBe(503);
   expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_child_withdrawals').first('n')).toBe(1);
  }finally{svc.close();}
 });
 it('rejects a challenge from another original child before claiming its proof',async()=>{
  const other=decodeNativeOriginal({...o,core_purpose_id:'other-http-child'});await job(other,'44444444-4444-4444-8444-444444444444','A'.repeat(42)+'E','other-native-claim');
  const svc=receiving();try{
   const before=await store.nativeJob(c.challenge_id);const result=await svc.handle(privateRequest('native/complete',{...serverInput(other.core_purpose_id),challenge_id:c.challenge_id,native_proof:await assertion(o,c)}));expect(result.status).toBe(404);expect(await store.nativeJob(c.challenge_id)).toEqual(before);
  }finally{svc.close();}
 });
 it('rejects a missing or substituted atomic receiving guard before any positive Source181 insertion',async()=>{
  const svc=receiving(),original={...o,core_purpose_id:'without-guard'};await env.DB.prepare('DROP TRIGGER host_wake_receiving_registration_guard').run();
  try{const result=await svc.handle(privateRequest('issuer/issue',{...serverInput(original.core_purpose_id),original}));expect(result.status).toBe(503);expect(await store.issuer('authorization',original.core_purpose_id)).toBeNull();}
  finally{svc.close();await env.DB.prepare(regGuard).run();}
 });
 it('does not accept a replaced enrolled public key under an unchanged SDK identifier',async()=>{
  const changed=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;await env.DB.prepare('UPDATE host_wake_native_enrollments SET public_key_spki_b64=?').bind(b64(new Uint8Array(await crypto.subtle.exportKey('spki',changed.publicKey) as ArrayBuffer))).run();
  const issuer=(await store.issuer('authorization',o.core_purpose_id))!,w=clock();try{await expect(bindSource181(sourceEnv,issuer,'record',w,fetch,16)).rejects.toThrow('host_wake_native_policy_unavailable');}finally{w.close();}
 });

 async function operatorRequest(path:string,value:unknown,secret='synthetic-operator-http-key-not-production'){
  const text=JSON.stringify(value),timestamp=String(Math.floor(Date.now()/1000)),key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const signature=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(timestamp+'.'+text));return new Request('https://local.test'+path,{method:'POST',headers:{'content-type':'application/json','x-djconnect-timestamp':timestamp,'x-djconnect-signature':[...new Uint8Array(signature)].map(b=>b.toString(16).padStart(2,'0')).join('')},body:text});
 }
 it('authenticates actual operator HMAC and persists/withdraws the same retained role without a provider dependency',async()=>{
  const config={...env,DJCONNECT_RELAY_SECRET:'synthetic-operator-http-key-not-production'} as AppEnv,svc=receiving(config);
  const a=decodeOperatorAuthorization(JSON.parse((await store.authorization('authorization'))!.authorization_json));
  try{
   const grant={...a,authorization_id:'operator-http-role',operation_id:'operator-http-operation'};const result=await svc.handle(await operatorRequest(OPERATOR_AUTHORIZE,grant));expect(result.status).toBe(200);expect((await store.authorization(grant.authorization_id))?.outcome).toBe('authorized');
   const path='/v1/push/host-app-wake/operator/withdraw',withdraw={version:RECEIVING_VERSION,method:'POST',route:path,action:'withdraw',operation_id:'operator-http-withdrawal',authorization_id:grant.authorization_id};
   expect((await svc.handle(await operatorRequest(path,withdraw))).status).toBe(200);expect((await store.authorization(grant.authorization_id))?.outcome).toBe('withdrawn');
   expect((await svc.handle(await operatorRequest(OPERATOR_AUTHORIZE,grant))).status).toBe(200);expect((await store.authorization(grant.authorization_id))?.outcome).toBe('withdrawn');
  }finally{svc.close();}
 });
 it('does not acknowledge a missing operator role or mutate under invalid HMAC/Bearer fallback',async()=>{
  const config={...env,DJCONNECT_RELAY_SECRET:'synthetic-operator-http-key-not-production'} as AppEnv,svc=receiving(config);
  try{
   const path='/v1/push/host-app-wake/operator/withdraw',withdraw={version:RECEIVING_VERSION,method:'POST',route:path,action:'withdraw',operation_id:'unknown-withdrawal',authorization_id:'missing-role'};
   expect((await svc.handle(await operatorRequest(path,withdraw))).status).toBe(404);
   const request=await operatorRequest(path,{...withdraw,authorization_id:'authorization'});request.headers.set('authorization','Bearer '+config.DJCONNECT_RELAY_SECRET);expect((await svc.handle(request)).status).toBe(401);expect((await store.authorization('authorization'))?.outcome).toBe('authorized');
  }finally{svc.close();}
 });

 it('blocks the actual delayed Source181 INSERT after negative closure; absent-guard control demonstrates the old gap',async()=>{
  const original=decodeNativeOriginal({...o,core_purpose_id:'late-source-insert'});await store.reserveIssuer('authorization','record','late-source-issuer','8'.repeat(64),original,'late-source-private','late-source-claim',at,at,'app_attest_assertion');
  const issuer=(await store.issuer('authorization',original.core_purpose_id))!,w=clock(),backend=await bindSource181(sourceEnv,issuer,'record',w,fetch,16),source=new WakeStore(env.DB);
  try{
   await store.withdrawIssuer('authorization',original.core_purpose_id,'record');
   await env.DB.prepare('DROP TRIGGER host_wake_receiving_issuer_guard').run();
   try{expect(await source.issue(backend.scope,'synthetic-noncredential-hash','before-guard-control',16,Date.now())).toBe(true);}
   finally{await env.DB.prepare("DELETE FROM host_app_wake_purposes WHERE purpose_id='late-source-private'").run();await env.DB.prepare(issuerGuard).run();}
   await expect(source.issue(backend.scope,'synthetic-noncredential-hash','after-guard-control',16,Date.now())).rejects.toThrow('host_wake_issuer_eligibility');expect(await env.DB.prepare("SELECT COUNT(*) n FROM host_app_wake_purposes WHERE purpose_id='late-source-private'").first('n')).toBe(0);
  }finally{backend.close();w.close();}
 });
 it('retains the original ten-second body budget before operator authentication or grant allocation',async()=>{
  let time=Date.now();const config={...env,DJCONNECT_RELAY_SECRET:'synthetic-unused-operator-key'} as AppEnv,svc=createReceivingService({env:config,capacity:16,now:()=>time,fetcher:fetch});
  let controller:ReadableStreamDefaultController<Uint8Array>;const stream=new ReadableStream<Uint8Array>({start(value){controller=value;}});
  try{const pending=svc.handle(new Request('https://local.test'+OPERATOR_AUTHORIZE,{method:'POST',headers:{'content-type':'application/json'},body:stream}));await Promise.resolve();time+=10001;controller!.enqueue(new TextEncoder().encode('{}'));controller!.close();const result=await pending;expect(result.status).toBe(409);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_operator_authorizations').first('n')).toBe(1);}
  finally{svc.close();}
 });

 it('reports an abandoned issuer reservation expired at its original callback boundary, without a fresh pending window',async()=>{
  const original=decodeNativeOriginal({...o,core_purpose_id:'old-reserved-http-child'}),input=serverInput(original.core_purpose_id);
  await store.reserveIssuer('authorization','record',input.issuer_operation_id,'9'.repeat(64),original,'old-reserved-private','old-reserved-claim',at,at,'app_attest_assertion');
  await env.DB.prepare('UPDATE host_wake_issuer_once SET original_request_expires_at=? WHERE core_purpose_id=?').bind(Date.now()-1,original.core_purpose_id).run();
  const svc=receiving();try{const response=await svc.handle(privateRequest('issuer/status',input));expect(response.status).toBe(200);const result=await response.json() as Record<string,unknown>;expect(result.state).toBe('expired');expect(result.credential_state).toBe('unavailable');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n')).toBe(0);}finally{svc.close();}
 });

 function targetInput(kind:'register'|'wake'|'status'|'revoke',operation=o.operation_id){
  const base={version:SOURCE_VERSION,purpose_id:'private-'+o.core_purpose_id,operation_id:operation};
  return kind==='register'?{...base,generation:o.generation,revision:o.revision,token_role:'host_app_wake' as const,target:o.target,apns_environment:o.apns_environment,apns_token:vectors.native_token_hex}:kind==='wake'?{...base,generation:o.generation,revision:o.revision,event:'direct_rich_refresh' as const}:base;
 }
 function targetRequest(kind:'register'|'wake'|'status'|'revoke',value=targetInput(kind),overrides:Record<string,string>={}){
  return new Request('https://local.test'+PREFIX+kind,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer djci_'+'A'.repeat(43),'x-djconnect-host-wake-authorization-id':'authorization','x-djconnect-host-wake-core-purpose-id':o.core_purpose_id,'x-djconnect-host-wake-issuer-operation-id':'issuer-'+o.core_purpose_id,[TARGET_CAPABILITY_HEADER]:capabilities.get(o.core_purpose_id)!,...(kind==='register'||kind==='wake'?{[TARGET_OPERATION_HEADER]:value.operation_id}:{}),...overrides},body:JSON.stringify(value)});
 }
 async function verifyFixtureProof(){const w=clock();try{expect(await commitVerifiedAssertion((await verified(w))!,w)).toBe(true);}finally{w.close();}}
 async function softwareProviderConfig(){
  const provider=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;
  const bytes=new Uint8Array(await crypto.subtle.exportKey('pkcs8',provider.privateKey) as ArrayBuffer);return {...sourceEnv,APNS_PRIVATE_KEY:'-----BEGIN PRIVATE KEY-----\n'+b64(bytes)+'\n-----END PRIVATE KEY-----'} as AppEnv;
 }
 it('runs actual private target register, one synthetic provider transport, correlated status and negative revoke with unchanged Source181 bodies',async()=>{
  await verifyFixtureProof();let calls=0;const config=await softwareProviderConfig(),svc=createReceivingService({env:config,capacity:16,now:()=>Date.now(),fetcher:async(url,init)=>{calls++;expect(String(url)).toBe('https://api.sandbox.push.apple.com/3/device/'+vectors.native_token_hex);expect(init?.body).toBe('{"aps":{"content-available":1}}');return new Response(null,{status:200});}});
  try{
   const input=targetInput('register'),registered=await svc.handle(targetRequest('register',input));expect(registered.status).toBe(200);expect(await registered.json()).toMatchObject({state:'registered',operation_state:'registered'});expect(calls).toBe(0);
   expect(registered.headers.get(TARGET_REQUEST_HASH_HEADER)).toBe(await sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',PREFIX+'register',input])));
   const wake=await svc.handle(targetRequest('wake',targetInput('wake','actual-fixture-wake-event')));expect(wake.status).toBe(200);expect(await wake.json()).toMatchObject({state:'registered',operation_state:'provider_accepted',provider_status:200});expect(calls).toBe(1);
   const status=await svc.handle(targetRequest('status'));expect(status.status).toBe(200);expect(await status.json()).toMatchObject({state:'registered',operation_state:'registered'});
   const negative=receiving({...env} as AppEnv,1);try{const revoke=await negative.handle(targetRequest('revoke'));expect(revoke.status).toBe(200);const out=await revoke.json() as Record<string,unknown>;expect(out.state).toBe('withdrawn');expect(out.operation_state).toBe('registered');expect(decodeTargetReply(out,input,o,input.purpose_id).state).toBe('withdrawn');expect((await negative.handle(targetRequest('status'))).status).toBe(200);}
   finally{negative.close();}
   expect(calls).toBe(1);expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT ciphertext FROM host_app_wake_purposes').first('ciphertext')).toBeNull();
  }finally{svc.close();}
 });
 it('requires the actual djci plus the separate exact capability and rejects combined capability before allocating an intent',async()=>{
  const svc=receiving();try{
   const wrong=targetRequest('register',undefined,{[TARGET_CAPABILITY_HEADER]:'djchw_'+'Z'.repeat(43)});expect((await svc.handle(wrong)).status).toBe(401);
   const combined=targetRequest('register',undefined,{[TARGET_CAPABILITY_HEADER]:capabilities.get(o.core_purpose_id)+', '+capabilities.get(o.core_purpose_id)});expect((await svc.handle(combined)).status).toBe(401);
   const bearer=targetRequest('register');bearer.headers.set('authorization','Bearer '+capabilities.get(o.core_purpose_id));expect((await svc.handle(bearer)).status).toBe(401);
   expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n')).toBe(0);
  }finally{svc.close();}
 });
 it('binds target operation header before body and leaves a failed mismatch UNKNOWN without Source181 mutation',async()=>{
  await verifyFixtureProof();const svc=receiving();try{
   expect((await svc.handle(targetRequest('register',undefined,{[TARGET_OPERATION_HEADER]:'different-body-operation'}))).status).toBe(403);
   expect(await env.DB.prepare('SELECT outcome FROM host_wake_receiving_intents').first('outcome')).toBe('unknown');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_app_wake_operations').first('n')).toBe(0);
  }finally{svc.close();}
 });
 it('does not retry an original target operation after a lost/consumed HTTP attempt or manufacture a second proof consumption',async()=>{
  await verifyFixtureProof();const svc=receiving();try{
   expect((await svc.handle(targetRequest('register'))).status).toBe(200);const consumed=await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at');
   expect((await svc.handle(targetRequest('register'))).status).toBe(409);expect(await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at')).toBe(consumed);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_app_wake_operations').first('n')).toBe(1);
  }finally{svc.close();}
 });
 it('terminally closes an unsupported changed native token at its first target-register boundary',async()=>{
  await verifyFixtureProof();const svc=receiving();try{
   expect((await svc.handle(targetRequest('register',{...targetInput('register'),apns_token:'ab'.repeat(32)}))).status).toBe(403);expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_app_wake_operations').first('n')).toBe(0);
  }finally{svc.close();}
 });
 it('does not report a positive active target status after its actual native enrollment retires',async()=>{
  await verifyFixtureProof();const svc=receiving();try{
   expect((await svc.handle(targetRequest('register'))).status).toBe(200);await env.DB.prepare('UPDATE host_wake_native_enrollments SET disabled=1').run();expect((await svc.handle(targetRequest('status'))).status).toBe(503);
  }finally{svc.close();}
 });
 it('retains prebody wake capture in the unchanged Source181 durable operation after delayed private authentication/body awaits',async()=>{
  await verifyFixtureProof();const first=receiving();try{expect((await first.handle(targetRequest('register'))).status).toBe(200);}finally{first.close();}
  const captured=Date.now();let time=captured,calls=0;const config=await softwareProviderConfig(),svc=createReceivingService({env:config,capacity:16,now:()=>time,fetcher:async()=>{calls++;return new Response(null,{status:200});}}),input=targetInput('wake','delayed-original-event');
  let streamController:ReadableStreamDefaultController<Uint8Array>;const stream=new ReadableStream<Uint8Array>({start(c){streamController=c;}}),template=targetRequest('wake',input);
  try{
   const pending=svc.handle(new Request(template.url,{method:'POST',headers:template.headers,body:stream}));await Promise.resolve();time+=5000;streamController!.enqueue(new TextEncoder().encode(JSON.stringify(input)));streamController!.close();const response=await pending;expect(response.status).toBe(200);expect(calls).toBe(1);
   const row=await env.DB.prepare('SELECT accepted_at,expires_at FROM host_app_wake_operations WHERE operation_id=?').bind(input.operation_id).first<{accepted_at:number;expires_at:number}>();expect(row!.accepted_at).toBe(captured);expect(row!.expires_at).toBe(captured+30000);
  }finally{svc.close();}
 });

 it('never sends a second synthetic provider request after cancellation/lost reply for the same original wake event',async()=>{
  await verifyFixtureProof();const first=receiving();try{expect((await first.handle(targetRequest('register'))).status).toBe(200);}finally{first.close();}
  const controller=new AbortController();let calls=0;const config=await softwareProviderConfig(),svc=createReceivingService({env:config,capacity:16,now:()=>Date.now(),fetcher:async()=>{calls++;controller.abort();return new Response(null,{status:200});}}),input=targetInput('wake','lost-response-original-event'),template=targetRequest('wake',input);
  try{
   const result=await svc.handle(new Request(template,{signal:controller.signal}));expect(result.status).toBe(409);expect(calls).toBe(1);
   await vi.waitFor(async()=>{const row=await env.DB.prepare('SELECT outcome FROM host_app_wake_operations WHERE operation_id=?').bind(input.operation_id).first<{outcome:string}>();expect(row?.outcome).toBe('unknown');},{timeout:1000,interval:5});
   expect((await svc.handle(targetRequest('wake',input))).status).toBe(409);expect(calls).toBe(1);expect(await env.DB.prepare("SELECT COUNT(*) n FROM host_app_wake_operations WHERE operation_id=?").bind(input.operation_id).first('n')).toBe(1);
  }finally{svc.close();}
 });
 it('revokes an existing child even when the separate early-negative fence table is actually at capacity',async()=>{
  await verifyFixtureProof();const first=receiving();try{expect((await first.handle(targetRequest('register'))).status).toBe(200);}finally{first.close();}
  expect(await new ReceivingStore(env.DB,1).withdrawIssuer('authorization','other-earlier-negative','record')).toBe(true);
  const negative=receiving({...env} as AppEnv,1);try{expect((await negative.handle(targetRequest('revoke'))).status).toBe(200);expect((await store.issuer('authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_child_withdrawals').first('n')).toBe(1);expect(await env.DB.prepare('SELECT ciphertext FROM host_app_wake_purposes').first('ciphertext')).toBeNull();}finally{negative.close();}
 });

});
