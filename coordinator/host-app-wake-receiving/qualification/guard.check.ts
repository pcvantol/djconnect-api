import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,it,expect} from 'vitest';
import schema from '../schema.sql?raw';
import guard from '../dispatch-guard.sql?raw';
import hostSchema from '../../host-app-wake/schema.sql?raw';
import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import {WakeStore} from '../../host-app-wake/store';
import {original,VERSION} from '../../host-app-wake/wire';
import {canonical} from '../../../src/surface-push/wire';
import vectors from './native-transcript-vectors.json';
import {ReceivingStore} from '../receiving-store';
import {decodeNativeOriginal,decodeOperatorAuthorization,OPERATOR_AUTHORIZE,RECEIVING_VERSION} from '../wire';
// Fixture-only seeded enrollment/policy/proof. This exercises actual SQL marker
// constraints, NOT a real enrollment writer, key, proof, clock or provider.
let at:number,o:ReturnType<typeof decodeNativeOriginal>,p:ReturnType<typeof original>,wake:WakeStore;
async function initialize(){
 at=Date.now()-1000;o=decodeNativeOriginal({...vectors.original,native_key_id_b64:btoa('A'.repeat(32)),original_wake_issued_at_ms:at,original_wake_expires_at_ms:at+3600000,original_display_expires_at_ms:at+7200000});
 const {native_key_id_b64,native_token_sha256,core_purpose_id,operation_id,generation,revision,token_role,original_wake_issued_at_ms,original_wake_expires_at_ms,original_display_expires_at_ms,version,...scope}=o;
 const a=decodeOperatorAuthorization({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',authorization_id:'authorization',operation_id:'operator-op',core_install_token_record_id:'record',ha_install_id:'install',native_key_ref:'native-record',...scope,max_original_purpose_ms:28800000,max_operations:256,max_reserved_sends:64,original_authorization_issued_at_ms:at,original_authorization_expires_at_ms:at+7200000});
 await env.DB.prepare("INSERT INTO install_tokens(id,ha_install_id,token_hash,token_prefix) VALUES ('record','install','fixture-only-token-hash','djci_fixture')").run();
 const r=new ReceivingStore(env.DB,10);await r.authorize(a,'a'.repeat(64),at,at);await r.reserveIssuer('authorization','record','issuer-op','b'.repeat(64),o,'private-purpose','internal-claim',at,at);await r.finishIssuer('authorization',o.core_purpose_id,'issued',at);
 const c={...vectors.challenge,captured_at_ms:at,expires_at_ms:at+30000};await r.reserveNativeJob('authorization','record',o,c,'c'.repeat(64),'app_attest_assertion',at);
 await env.DB.prepare("UPDATE host_wake_native_jobs SET outcome='verified'").run();
 await env.DB.prepare(`INSERT INTO host_wake_native_enrollments(native_key_ref,native_key_id_b64,public_key_spki_b64,host_bundle,install_id,platform,environment,identity_policy_sha256,deployment_policy_sha256,enrollment_receipt_sha256,signed_environment_receipt_sha256,issued_at,expires_at,counter) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('native-record',o.native_key_id_b64,'synthetic-not-a-public-key',o.target.host_bundle_id,o.target.installation_id,o.platform,o.apns_environment,o.identity_policy_sha256,o.deployment_policy_sha256,'e'.repeat(64),'f'.repeat(64),at,at+7200000,1).run();
 await env.DB.prepare('INSERT INTO host_wake_native_verifications(challenge_id,native_key_ref,verified_counter,original_json) VALUES (?,?,?,?)').bind(c.challenge_id,'native-record',1,canonical(o)).run();
 p=original({version:VERSION,purpose_id:'private-purpose',token_role:'host_app_wake',owner_binding:o.owner_binding,device_binding:o.device_binding,source_binding:o.source_binding,target:o.target,apns_environment:o.apns_environment,platform:o.platform,issued_at_ms:at,expires_at_ms:at+3600000,display_expires_at_ms:at+7200000,max_operations:256,max_wakes:64});
 wake=new WakeStore(env.DB);expect(await wake.issue(p,'credential-hash','claim',10,at)).toBe(true);
 await env.DB.prepare("UPDATE host_app_wake_purposes SET generation=?,revision=?,ciphertext='fixture-sealed',nonce='fixture-nonce'").bind(o.generation,o.revision).run();
 await env.DB.prepare(`INSERT INTO host_app_wake_operations(purpose_id,operation_id,request_hash,kind,claim_id,generation,revision,accepted_at,expires_at,outcome) VALUES ('private-purpose','wake-op','fixture-hash','wake','wake-claim',?,?,?,?,'reserved')`).bind(o.generation,o.revision,at,at+30000).run();
}
async function marker(){return wake.mark(p,{version:VERSION,purpose_id:p.purpose_id,operation_id:'wake-op',generation:o.generation,revision:o.revision},'wake-claim',Date.now());}
describe('actual Source181 marker guarded atomically by local D1 eligibility, fixture authority only',()=>{
 beforeAll(async()=>{for(const text of [installSchema,hostSchema,schema])for(const statement of text.replace(/--[^\n]*/g,'').split(';').filter(x=>x.trim()))await env.DB.prepare(statement).run();await env.DB.prepare(guard).run();});
 beforeEach(async()=>{for(const table of ['host_wake_native_verifications','host_wake_native_enrollments','host_wake_native_jobs','host_wake_issuer_once','host_wake_operator_authorizations','host_app_wake_operations','host_app_wake_purposes','install_tokens'])await env.DB.prepare('DELETE FROM '+table).run();await initialize();});
 it('allows exactly one marker with all locally current fixture rows matching, without any outbound call',async()=>{
  expect(await marker()).toBe(true);expect(await marker()).toBe(false);
 });
 it.each([
  "UPDATE install_tokens SET disabled=1",
  "UPDATE host_wake_operator_authorizations SET outcome='withdrawn'",
  'UPDATE host_wake_operator_authorizations SET expires_at=issued_at+1',
  "UPDATE host_wake_issuer_once SET outcome='unknown'",
  "UPDATE host_wake_native_jobs SET outcome='unknown'",
  "DELETE FROM host_wake_native_verifications",
  "UPDATE host_wake_native_verifications SET verified_counter=2",
  "UPDATE host_wake_native_enrollments SET disabled=1",
  "UPDATE host_wake_native_enrollments SET expires_at=issued_at+1",
  "UPDATE host_wake_native_enrollments SET environment='production'",
  "UPDATE host_wake_native_enrollments SET host_bundle='example.other.host'",
  "UPDATE host_wake_native_enrollments SET native_key_id_b64='YWJj'",
  "UPDATE host_wake_native_enrollments SET signed_environment_receipt_sha256=''",
  "UPDATE host_wake_native_enrollments SET enrollment_receipt_sha256=''",
  "UPDATE host_wake_native_enrollments SET identity_policy_sha256='changed'",
  "UPDATE host_wake_native_enrollments SET deployment_policy_sha256='changed'",
  "UPDATE host_wake_native_verifications SET original_json='{}'",
  "UPDATE host_app_wake_purposes SET scope_json='{}'",
 ])('denies a marker after the actual local state changes: %s',async sql=>{
  await env.DB.prepare(sql).run();await expect(marker()).rejects.toThrow('host_wake_dispatch_eligibility');
  expect((await wake.operation(p.purpose_id,'wake-op'))?.outcome).toBe('reserved');
 });
 it('denies missing authorization/native policy even if the standalone Source181 purpose remains valid',async()=>{
  await env.DB.prepare('DELETE FROM host_wake_native_verifications').run();await expect(marker()).rejects.toThrow();
 });
});
