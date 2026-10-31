import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,it,expect,vi} from 'vitest';
import cbor from 'cbor';
import type {AppEnv} from '../../../src/types';
import {sha256Hex} from '../../../src/crypto';
import {canonical} from '../../../src/surface-push/wire';
import {decodeNativeOriginal,decodeOperatorAuthorization,RECEIVING_VERSION,OPERATOR_AUTHORIZE} from '../wire';
import {decodeNativePolicy,decodeLaunchCategory,OPERATOR_NATIVE_POLICY,OPERATOR_NATIVE_WITHDRAW} from '../native-policy';
import {createReceivingService} from '../service';
import {verifySavedAttestation,commitVerifiedAttestation} from '../native-attestation';
import {verifyAppleAttestationEvidence} from '../native-apple-evidence.mjs';
import {nativePolicyRow} from '../native-policy-store';
import {ReceivingStore} from '../receiving-store';
import {RequestWindow} from '../request-window';
import vectors from './native-transcript-vectors.json';
import schema from '../schema.sql?raw';import hostSchema from '../../host-app-wake/schema.sql?raw';import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import eligibility from '../eligibility-view.sql?raw';import registration from '../registration-guard.sql?raw';import dispatch from '../dispatch-guard.sql?raw';import issuer from '../issuer-guard.sql?raw';import firstJob from '../native-first-job-guard.sql?raw';import keyInsert from '../native-key-insert-guard.sql?raw';import firstProof from '../native-first-proof-guard.sql?raw';
// MODEL ONLY: no Apple certificate/signature/receipt/status is qualified here.
// This loader mock is absent from the production module's import graph.
const modeled=vi.hoisted(()=>({spki:'',badSpki:'',badKey:false}));
vi.mock('../native-apple-evidence.mjs',async original=>{const actual=await original<typeof import('../native-apple-evidence.mjs')>();return {...actual,verifyAppleAttestationEvidence:async()=>({scope:'APPLE_ATTESTATION_AND_RECEIPT_CRYPTO_STATUS_ONLY_NO_ENROLLMENT',public_key_spki_b64:modeled.badKey?modeled.badSpki:modeled.spki,receipt:new TextEncoder().encode('SYNTHETIC MODELED RECEIPT; NOT APPLE EVIDENCE'),receiptCreated:Date.now()-1,expires:Date.now()+3600000,attestationPathScope:'MODELED_NOT_QUALIFIED',receiptScope:'MODELED_NOT_QUALIFIED',statusCheckedAt:Date.now()-1,statusExpiresAt:Date.now()+60000})};});
const secret='synthetic-operator-enrollment-only-not-a-real-secret',token='djci_'+'A'.repeat(43),challenge='88888888-8888-4888-8888-888888888888';
let issuedCap:string;let keyId:string;let at:number,config:AppEnv,o:ReturnType<typeof decodeNativeOriginal>,policy:ReturnType<typeof decodeNativePolicy>,store:ReceivingStore,fetches:number;
function service(capacity=16){return createReceivingService({env:config,capacity,now:()=>Date.now(),fetcher:async()=>{fetches++;throw Error('NO ACTUAL APPLE/SDK/PROVIDER NETWORK IN NEGATIVE QUALIFICATION');}});}
async function signed(path:string,body:unknown){const raw=JSON.stringify(body),timestamp=String(Math.floor(Date.now()/1000)),key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']),sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(timestamp+'.'+raw)));return new Request('https://local.test'+path,{method:'POST',headers:{'content-type':'application/json','x-djconnect-timestamp':timestamp,'x-djconnect-signature':[...sig].map(b=>b.toString(16).padStart(2,'0')).join('')},body:raw});}
function input(purpose=o.core_purpose_id){return {version:RECEIVING_VERSION,authorization_id:'native-authorization',core_purpose_id:purpose,issuer_operation_id:'native-issuer-'+purpose};}
function request(route:string,body:Record<string,unknown>){return new Request('https://local.test/v1/push/host-app-wake/'+route,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token,'x-djconnect-host-wake-authorization-id':String(body.authorization_id),'x-djconnect-host-wake-core-purpose-id':String(body.core_purpose_id),'x-djconnect-host-wake-issuer-operation-id':String(body.issuer_operation_id)},body:JSON.stringify(body)});}
async function installPending(svc:ReturnType<typeof service>){const r=await svc.handle(await signed(OPERATOR_NATIVE_POLICY,policy));expect(r.status).toBe(200);expect(await r.json()).toMatchObject({outcome:'pending'});}
async function issueAndChallenge(svc:ReturnType<typeof service>){const issued=await svc.handle(request('issuer/issue',{...input(),original:o}));expect(issued.status).toBe(200);const issuedBody=await issued.json() as Record<string,unknown>;expect(issuedBody).toMatchObject({state:'issued',native_proof_kind:'app_attest_attestation'});issuedCap=String(issuedBody.credential);const r=await svc.handle(request('native/challenge',{...input(),challenge_id:challenge}));expect(r.status).toBe(200);return r.json() as Promise<Record<string,unknown>>;}
describe('MODELED Apple evidence ONLY: actual D1 first-enrollment transaction/once/guard qualification; NO NATIVE TRUST GO',()=>{
 beforeAll(async()=>{for(const text of [installSchema,hostSchema,schema])for(const sql of text.replace(/--[^\n]*/g,'').split(';').filter(v=>v.trim()))await env.DB.prepare(sql).run();for(const sql of [eligibility,registration,dispatch,issuer,firstJob,keyInsert,firstProof])await env.DB.prepare(sql).run();});
 beforeEach(async()=>{
  for(const table of ['host_wake_native_verifications','host_wake_native_enrollments','host_wake_native_pending_policies','host_wake_child_withdrawals','host_wake_receiving_intents','host_wake_native_jobs','host_wake_issuer_once','host_wake_operator_authorizations','host_app_wake_operations','host_app_wake_purposes','install_tokens'])await env.DB.prepare('DELETE FROM '+table).run();
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair,point=await crypto.subtle.exportKey('raw',pair.publicKey) as ArrayBuffer;
  keyId=btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256',point))));modeled.spki=btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey) as ArrayBuffer)));modeled.badKey=false;
  const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;modeled.badSpki=btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('spki',other.publicKey) as ArrayBuffer)));
  at=Date.now()-100;fetches=0;config={...env,DJCONNECT_RELAY_SECRET:secret,APNS_TEAM_ID:'ABCDEFGHIJ',APNS_TOPIC_IOS:'example.fixture.host',APNS_ENVIRONMENT:'sandbox',APNS_TOKEN_ENCRYPTION_KEY:btoa('0123456789abcdef0123456789abcdef')} as AppEnv;store=new ReceivingStore(env.DB,16);
  o=decodeNativeOriginal({...vectors.original,native_key_id_b64:keyId,original_wake_issued_at_ms:at,original_wake_expires_at_ms:at+3600000,original_display_expires_at_ms:at+7200000});
  const {version,native_key_id_b64,native_token_sha256,core_purpose_id,operation_id,generation,revision,token_role,original_wake_issued_at_ms,original_wake_expires_at_ms,original_display_expires_at_ms,...scope}=o;
  await env.DB.prepare("INSERT INTO install_tokens(id,ha_install_id,token_hash,token_prefix) VALUES('native-record','native-install',?,'djci_fixture')").bind(await sha256Hex(token)).run();
  await store.authorize(decodeOperatorAuthorization({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',operation_id:'native-operator-operation',authorization_id:'native-authorization',core_install_token_record_id:'native-record',ha_install_id:'native-install',native_key_ref:'pending-native-key',...scope,max_original_purpose_ms:28800000,max_operations:64,max_reserved_sends:16,original_authorization_issued_at_ms:at-1,original_authorization_expires_at_ms:at+7200000}),'a'.repeat(64),at,at);
  policy=decodeNativePolicy({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_NATIVE_POLICY,action:'native_policy',operation_id:'native-policy-operation',authorization_id:'native-authorization',native_key_ref:'pending-native-key',native_key_id_b64:keyId,profile:'host_wake_apple_properties_attestation_v2',app_identifier:'ABCDEFGHIJ.'+o.target.host_bundle_id,apns_team_id:'ABCDEFGHIJ',app_attest_environment:'development',bundle_version:'1.0',launch_validation_category_b64:btoa(String.fromCharCode(3,0,0,0)),signed_host_artifact_sha256:'b'.repeat(64),signed_environment_receipt_sha256:'c'.repeat(64),scope,original_policy_issued_at_ms:at,original_policy_expires_at_ms:at+7200000});
 });

 async function staged(){const svc=service();await installPending(svc);await issueAndChallenge(svc);return svc;}
 function complete(){return request('native/complete',{...input(),challenge_id:challenge,native_proof:{kind:'app_attest_attestation',bytes_b64:btoa('MODELED; NOT A REAL APPLE PROOF')}});}
 async function branded(){
  const claim='modeled-private-claim';expect(await store.claimNativeProof('native-authorization','native-record',challenge,'app_attest_attestation',claim,Date.now())).toBe(true);
  const window=new RequestWindow(()=>Date.now(),new AbortController().signal),receipt=await verifySavedAttestation(env.DB,config,'native-authorization','native-record',challenge,claim,{kind:'app_attest_attestation',bytes_b64:btoa('MODEL')},window,fetch,16);expect(receipt).not.toBeNull();return {claim,window,receipt:receipt!};
 }
 it('MODEL ONLY: reaches the real zero-counter key/proof transaction, encrypted storage and exact original native_verified reply',async()=>{
  const svc=await staged();try{const response=await svc.handle(complete());expect(response.status).toBe(200);const body=await response.json() as Record<string,unknown>;expect(body.state).toBe('native_verified');expect(body.native_proof_kind).toBe('app_attest_attestation');expect(Object.hasOwn(body,'receipt')).toBe(false);
   const n=await env.DB.prepare('SELECT * FROM host_wake_native_enrollments').first<Record<string,unknown>>();expect(n!.counter).toBe(0);expect(n!.native_key_id_b64).toBe(keyId);expect(n!.public_key_spki_b64).toBe(modeled.spki);expect(n!.receipt_ciphertext).not.toContain('SYNTHETIC');expect(n!.receipt_nonce).toBeTypeOf('string');expect((await nativePolicyRow(env.DB,policy.native_key_ref))?.outcome).toBe('enrolled');expect((await store.nativeJob(challenge))?.outcome).toBe('verified');expect(await env.DB.prepare('SELECT verified_counter FROM host_wake_native_verifications').first('verified_counter')).toBe(0);expect(fetches).toBe(0);
   expect((await svc.handle(complete())).status).toBe(409);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_enrollments').first('n')).toBe(1);
  }finally{svc.close();}
 });
 it('MODEL ONLY: allows actual Source181 token registration to consume the one initial attestation receipt exactly once',async()=>{
  const svc=await staged();try{expect((await svc.handle(complete())).status).toBe(200);const row=(await store.issuer('native-authorization',o.core_purpose_id))!;
   const cap=issuedCap; // Actual one-time capability retained from issue, never recovered or rebound.
   const body={version:'djc-host-app-wake/1',purpose_id:row.private_purpose_id,operation_id:o.operation_id,generation:o.generation,revision:o.revision,token_role:'host_app_wake',target:o.target,apns_environment:o.apns_environment,apns_token:vectors.native_token_hex};
   const headers={'content-type':'application/json',authorization:'Bearer '+token,'x-djconnect-host-wake-authorization-id':'native-authorization','x-djconnect-host-wake-core-purpose-id':o.core_purpose_id,'x-djconnect-host-wake-issuer-operation-id':'native-issuer-'+o.core_purpose_id,'x-djconnect-host-wake-capability':cap,'x-djconnect-host-wake-operation-id':o.operation_id};
   const r=await svc.handle(new Request('https://local.test/v1/push/host-app-wake/register',{method:'POST',headers,body:JSON.stringify(body)}));expect(r.status).toBe(200);expect(await r.json()).toMatchObject({state:'registered',operation_state:'registered'});expect(await env.DB.prepare('SELECT consumed_at FROM host_wake_native_verifications').first('consumed_at')).toBeGreaterThan(0);expect(fetches).toBe(0);
  }finally{svc.close();}
 });
 it.each(['principal','operator','child','policy','nonce'] as const)('MODEL ONLY: denies commit after the real %s state retires, with no positive key or receipt',async changed=>{
  const svc=await staged(),v=await branded();try{
   if(changed==='principal')await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();
   if(changed==='operator')await store.withdrawAuthorization('native-authorization');
   if(changed==='child')await store.withdrawIssuer('native-authorization',o.core_purpose_id,'native-record');
   if(changed==='policy')await env.DB.prepare("UPDATE host_wake_native_pending_policies SET outcome='withdrawn'").run();
   if(changed==='nonce')await env.DB.prepare('UPDATE host_wake_native_jobs SET expires_at=?').bind(Date.now()-1).run();
   expect(await commitVerifiedAttestation(v.receipt,v.window)).toBe(false);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_enrollments').first('n')).toBe(0);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(0);
  }finally{v.window.close();svc.close();}
 });
 it('MODEL ONLY: serializes two opaque receipts for the same real job and never lends the winner ACK to another commit claim',async()=>{
  const svc=await staged(),v=await branded();try{
   const second=await verifySavedAttestation(env.DB,config,'native-authorization','native-record',challenge,v.claim,{kind:'app_attest_attestation',bytes_b64:btoa('SECOND MODEL')},v.window,fetch,16);expect(second).not.toBeNull();
   const results=await Promise.all([commitVerifiedAttestation(v.receipt,v.window),commitVerifiedAttestation(second!,v.window)]);expect(results.filter(Boolean)).toHaveLength(1);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_enrollments').first('n')).toBe(1);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(1);
   await expect(commitVerifiedAttestation(v.receipt,v.window)).rejects.toThrow('host_wake_native_crypto_receipt_required');
  }finally{v.window.close();svc.close();}
 });
 it('MODEL ONLY: aborts the complete actual D1 transaction if the native nonce expires at the guarded key INSERT boundary',async()=>{
  const svc=await staged(),v=await branded();try{
   await env.DB.prepare(`CREATE TRIGGER qualification_expire_native_before_insert BEFORE INSERT ON host_wake_native_enrollments WHEN NEW.native_policy_json IS NOT NULL BEGIN UPDATE host_wake_native_jobs SET expires_at=CAST(unixepoch('subsec')*1000 AS INTEGER)-1 WHERE private_job_id=NEW.enrollment_job_id; END`).run();
   try{await expect(commitVerifiedAttestation(v.receipt,v.window)).rejects.toThrow('host_wake_native_enrollment_context');}
   finally{await env.DB.prepare('DROP TRIGGER qualification_expire_native_before_insert').run();}
   expect((await nativePolicyRow(env.DB,policy.native_key_ref))?.outcome).toBe('pending');expect((await nativePolicyRow(env.DB,policy.native_key_ref))?.enrollment_claim).toBeNull();expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_enrollments').first('n')).toBe(0);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_verifications').first('n')).toBe(0);
  }finally{v.window.close();svc.close();}
 });
 it('MODEL ONLY: treats inconsistent trusted-kernel output as unavailable before minting an opaque receipt or inserting a key',async()=>{
  const svc=await staged();try{modeled.badKey=true;const r=await svc.handle(complete());expect(r.status).toBe(503);expect((await store.nativeJob(challenge))?.outcome).toBe('unknown');expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_enrollments').first('n')).toBe(0);}finally{svc.close();}
 });
 it('MODEL ONLY: a prepared child cannot switch its native proof kind after another child enrolls the shared pending key',async()=>{
  const svc=service();try{await installPending(svc);
   const other=decodeNativeOriginal({...o,core_purpose_id:'other-original-child',operation_id:'99999999-9999-4999-8999-999999999999'});
   const a=await svc.handle(request('issuer/issue',{...input(),original:o})),b=await svc.handle(request('issuer/issue',{...input(other.core_purpose_id),original:other}));expect(a.status).toBe(200);expect(b.status).toBe(200);expect(await b.json()).toMatchObject({native_proof_kind:'app_attest_attestation'});
   expect((await svc.handle(request('native/challenge',{...input(),challenge_id:challenge}))).status).toBe(200);expect((await svc.handle(complete())).status).toBe(200);
   const response=await svc.handle(request('native/challenge',{...input(other.core_purpose_id),challenge_id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}));expect(response.status).toBeGreaterThanOrEqual(400);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_native_jobs').first('n')).toBe(1);
  }finally{svc.close();}
 });

});
