import {describe,it,expect} from 'vitest';
import {authenticateOperator} from '../operator-auth';
import {decodeNativeOriginal,decodeNativeChallenge,nativeSigningData,checkNativeChallenge,decodeOperatorAuthorization,RECEIVING_VERSION,NATIVE_VERSION,NATIVE_DOMAIN,OPERATOR_AUTHORIZE,OPERATOR_WITHDRAW,MAX_BODY_BYTES,type NativeOriginalData} from '../wire';
import type {AppEnv} from '../../../src/types';
const NOW=Math.floor(Date.now()/1000)*1000,SECRET='synthetic-existing-operator-fixture-not-production';
function original():NativeOriginalData{return {version:NATIVE_VERSION,core_purpose_id:'fixture-original-display',operation_id:'11111111-1111-4111-8111-111111111111',generation:'fixture-original-generation',revision:1,token_role:'host_app_wake',target:{host_bundle_id:'example.fixture.host',installation_id:'fixture-native-install'},platform:'ipados',apns_environment:'sandbox',paired_subject_binding_sha256:'1'.repeat(64),owner_binding:'2'.repeat(64),device_binding:'3'.repeat(64),source_binding:'4'.repeat(64),selected_ha_origin_sha256:'5'.repeat(64),identity_policy_sha256:'6'.repeat(64),deployment_policy_sha256:'7'.repeat(64),native_key_id_b64:btoa('synthetic-sdk-key-id-not-an-enrolled-key'),native_token_sha256:'8'.repeat(64),original_wake_issued_at_ms:NOW,original_wake_expires_at_ms:NOW+3600000,original_display_expires_at_ms:NOW+7200000};}
function challenge(){return {challenge_id:'22222222-2222-4222-8222-222222222222',nonce_b64url:'A'.repeat(43),captured_at_ms:NOW,expires_at_ms:NOW+30000};}
function authorization(){const o=original();return {version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',operation_id:'fixture-original-operation',authorization_id:'fixture-authorization',core_install_token_record_id:'fixture-existing-install-record',ha_install_id:'fixture-existing-HA-install',paired_subject_binding_sha256:o.paired_subject_binding_sha256,owner_binding:o.owner_binding,device_binding:o.device_binding,source_binding:o.source_binding,selected_ha_origin_sha256:o.selected_ha_origin_sha256,identity_policy_sha256:o.identity_policy_sha256,deployment_policy_sha256:o.deployment_policy_sha256,target:o.target,platform:o.platform,apns_environment:o.apns_environment,native_key_ref:'fixture-known-private-native-key-record',max_original_purpose_ms:28800000,max_operations:256,max_reserved_sends:64,original_authorization_issued_at_ms:NOW,original_authorization_expires_at_ms:NOW+28800000};}
async function digest(b:Uint8Array<ArrayBufferLike>){const raw=await crypto.subtle.digest('SHA-256',Uint8Array.from(b));return [...new Uint8Array(raw)].map(v=>v.toString(16).padStart(2,'0')).join('');}
async function signed(path:string,body:unknown,alter?:string){const raw=typeof body==='string'?body:JSON.stringify(body),timestamp=String(Math.floor(Date.now()/1000));const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);const signature=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(timestamp+'.'+raw));const h=[...new Uint8Array(signature)].map(x=>x.toString(16).padStart(2,'0')).join('');return new Request('https://local.test'+path,{method:'POST',headers:{'content-type':'application/json','x-djconnect-timestamp':timestamp,'x-djconnect-signature':'sha256='+h},body:alter??raw});}
const env={DJCONNECT_RELAY_SECRET:SECRET} as AppEnv;
describe('receiving closed DATA grammar and actual existing HMAC channel, not native admission',()=>{
 it('serializes the original tuple plus nonce explicitly for independent client recomputation',async()=>{
  const o=original(),c=challenge(),d=nativeSigningData(o,c);expect(new TextDecoder().decode(d.client_data)).toBe(NATIVE_DOMAIN+d.canonical_utf8);expect(JSON.parse(d.canonical_utf8)).toEqual({original:o,challenge:c});
  const hash=await digest(d.client_data);expect((await checkNativeChallenge(o,c,d.canonical_utf8,hash)).client_data_sha256).toBe(hash);
 });
 it('refuses a bare opaque server hash or different canonical bytes',async()=>{
  const d=nativeSigningData(original(),challenge());await expect(checkNativeChallenge(original(),challenge(),'',await digest(d.client_data))).rejects.toThrow();await expect(checkNativeChallenge(original(),challenge(),d.canonical_utf8,'f'.repeat(64))).rejects.toThrow();
 });
 it.each(['core_purpose_id','generation','operation_id','native_key_id_b64'] as const)('binds the pre-await original %s',async field=>{
  const o=original(),c=challenge(),d=nativeSigningData(o,c);const changed=field==='operation_id'?'33333333-3333-4333-8333-333333333333':field==='native_key_id_b64'?btoa('other-synthetic-sdk-id'):'changed';decodeNativeOriginal({...o,[field]:changed});await expect(checkNativeChallenge({...o,[field]:changed},c,d.canonical_utf8,await digest(d.client_data))).rejects.toThrow();
 });
 it.each(['owner_binding','device_binding','source_binding','native_token_sha256','deployment_policy_sha256'] as const)('binds original digest %s',async field=>{
  const o=original(),c=challenge(),d=nativeSigningData(o,c);await expect(checkNativeChallenge({...o,[field]:'e'.repeat(64)},c,d.canonical_utf8,await digest(d.client_data))).rejects.toThrow();
 });
 it('does not infer native platform or APNs environment from Core client_type or App Attest',()=>{
  expect(()=>decodeNativeOriginal({...original(),platform:'ios',client_type:'ios'})).toThrow();expect(()=>decodeNativeOriginal({...original(),apns_environment:'appattestdevelop'})).toThrow();expect(decodeNativeOriginal(original()).platform).toBe('ipados');
 });
 it('bounds challenge by original wake/display expiry and 30s without replacing original lifetime',()=>{
  expect(()=>decodeNativeChallenge({...challenge(),expires_at_ms:NOW+30001},original())).toThrow();expect(()=>decodeNativeOriginal({...original(),original_display_expires_at_ms:NOW+1000})).toThrow();expect(()=>decodeNativeOriginal({...original(),original_wake_expires_at_ms:NOW+28800001,original_display_expires_at_ms:NOW+30000000})).toThrow();
 });
 it.each(['widget','live_activity_update','live_activity_start','host_app_background'])('refuses foreign/old token role %s',token_role=>{expect(()=>decodeNativeOriginal({...original(),token_role})).toThrow();});
 it.each([0,-0,1.5,257,NaN])('refuses ambiguous/out-of-range revision %s',revision=>{expect(()=>decodeNativeOriginal({...original(),revision})).toThrow();});
 it('refuses accessors and undeclared fields instead of calling them',()=>{
  const o=original();Object.defineProperty(o,'core_purpose_id',{get(){throw Error('getter executed');},enumerable:true});expect(()=>decodeNativeOriginal(o)).toThrow('host_wake_invalid');expect(()=>decodeNativeOriginal({...original(),read_credential:'forbidden'})).toThrow();
 });
 it('checks nonce canonical base64url including pad bits',()=>{
  expect(()=>decodeNativeChallenge({...challenge(),nonce_b64url:'A'.repeat(42)+'B'},original())).toThrow();expect(()=>decodeNativeChallenge({...challenge(),nonce_b64url:'A'.repeat(44)},original())).toThrow();
 });
 it('authenticates the actual existing operator HMAC over exact body and enforces signed route/action',async()=>{
  const a=authorization();expect(await authenticateOperator(await signed(OPERATOR_AUTHORIZE,a),env,'authorize')).toEqual(a);
  const w={version:RECEIVING_VERSION,method:'POST',route:OPERATOR_WITHDRAW,action:'withdraw',operation_id:'fixture-original-withdraw',authorization_id:'fixture-authorization'};expect(await authenticateOperator(await signed(OPERATOR_WITHDRAW,w),env,'withdraw')).toEqual(w);
 });
 it('refuses shared-secret Bearer even though the older helper accepts it',async()=>{
  const r=await signed(OPERATOR_AUTHORIZE,authorization());r.headers.set('authorization','Bearer '+SECRET);await expect(authenticateOperator(r,env,'authorize')).rejects.toThrow('host_wake_operator_hmac_required');
 });
 it('cannot move an authentic signed body to another operator route',async()=>{
  const a=authorization();await expect(authenticateOperator(await signed(OPERATOR_WITHDRAW,a),env,'withdraw')).rejects.toThrow();
 });
 it('refuses signed-body edits without a new authentic signature',async()=>{
  const a=authorization();await expect(authenticateOperator(await signed(OPERATOR_AUTHORIZE,a,JSON.stringify({...a,apns_environment:'production'})),env,'authorize')).rejects.toThrow();
 });
 it('refuses duplicate body keys even with an authentic exact HMAC',async()=>{
  const body=JSON.stringify(authorization());await expect(authenticateOperator(await signed(OPERATOR_AUTHORIZE,body.slice(0,-1)+',"action":"authorize"}'),env,'authorize')).rejects.toThrow();
 });
 it('rejects a large signed body before any unbounded buffering or original grant creation',async()=>{
  await expect(authenticateOperator(await signed(OPERATOR_AUTHORIZE,' '.repeat(MAX_BODY_BYTES+1)),env,'authorize')).rejects.toThrow('host_wake_size');
 });
 it.each([{max_original_purpose_ms:28800001},{max_reserved_sends:65},{max_operations:257},{action:'enrol'},{method:'GET'},{route:OPERATOR_WITHDRAW}])('closes operator wire/budgets %j',extra=>{expect(()=>decodeOperatorAuthorization({...authorization(),...extra})).toThrow();});
});
