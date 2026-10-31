import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,it,expect} from 'vitest';
import schema from '../schema.sql?raw';
import hostSchema from '../../host-app-wake/schema.sql?raw';
import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import vectors from './native-transcript-vectors.json';
import {ReceivingStore} from '../receiving-store';
import {decodeNativeOriginal,decodeOperatorAuthorization,OPERATOR_AUTHORIZE,RECEIVING_VERSION} from '../wire';
const START=1800000000000,END=START+7200000,o=decodeNativeOriginal(vectors.original),c=vectors.challenge;
function authorization(id='fixture-authorization',op='fixture-operator-operation'){
 const {native_key_id_b64,native_token_sha256,core_purpose_id,operation_id,generation,revision,token_role,original_wake_issued_at_ms,original_wake_expires_at_ms,original_display_expires_at_ms,version,...scope}=o;
 return decodeOperatorAuthorization({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',operation_id:op,authorization_id:id,core_install_token_record_id:'existing-record',ha_install_id:'existing-install',native_key_ref:'existing-native-record',...scope,max_original_purpose_ms:28800000,max_operations:256,max_reserved_sends:64,original_authorization_issued_at_ms:START,original_authorization_expires_at_ms:END});
}
let store:ReceivingStore;
async function grant(){return store.authorize(authorization(),'a'.repeat(64),START,START);}
async function issuer(hash='b'.repeat(64),claim='first-claim',captured=START,at=START){return store.reserveIssuer('fixture-authorization','existing-record','issuer-operation',hash,o,'private-API-purpose',claim,captured,at);}
async function clear(){for(const table of ['host_wake_native_verifications','host_wake_native_enrollments','host_wake_native_jobs','host_wake_issuer_once','host_wake_operator_authorizations','host_app_wake_operations','host_app_wake_purposes','install_tokens'])await env.DB.prepare('DELETE FROM '+table).run();}
describe('actual D1 receiving once-history with real existing install-token table, fixture authority only',()=>{
 beforeAll(async()=>{for(const text of [installSchema,hostSchema,schema])for(const statement of text.replace(/--[^\n]*/g,'').split(';').filter(x=>x.trim()))await env.DB.prepare(statement).run();});
 beforeEach(async()=>{await clear();await env.DB.prepare("INSERT INTO install_tokens (id,ha_install_id,token_hash,token_prefix) VALUES ('existing-record','existing-install','fixture-token-hash','djci_fixture')").run();store=new ReceivingStore(env.DB,2);});
 it('authorizes only an actual existing active record matching the exact HA installation',async()=>{
  expect((await grant()).outcome).toBe('authorized');expect(await store.isLive('fixture-authorization','existing-record',START)).toBe(true);
  expect(await store.isLive('fixture-authorization','other-record',START)).toBe(false);
  await expect(store.authorize({...authorization('other','other-op'),ha_install_id:'wrong-install'},'c'.repeat(64),START,START)).rejects.toThrow();
 });
 it('cannot create operator history for an unknown or retired principal',async()=>{
  await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();await expect(grant()).rejects.toThrow();expect(await store.authorization('fixture-authorization')).toBeNull();
 });
 it('preserves authenticated late-body/auth expiry as original terminal history',async()=>{
  const row=await store.authorize(authorization(),'a'.repeat(64),START,START+30000);expect(row.outcome).toBe('expired');
  const retry=await store.authorize(authorization(),'a'.repeat(64),START+30000,START+30000);expect(retry.outcome).toBe('expired');expect(retry.original_request_expires_at).toBe(START+30000);
 });
 it('rejects changed operator scope or transport-operation reuse instead of rebinding a grant',async()=>{
  await grant();await expect(store.authorize(authorization(),'c'.repeat(64),START,START)).rejects.toThrow();await expect(store.authorize(authorization('other'), 'a'.repeat(64),START,START)).rejects.toThrow();
 });
 it('retains withdrawn history at capacity and still permits terminal withdrawal',async()=>{
  store=new ReceivingStore(env.DB,1);await grant();await store.withdrawAuthorization('fixture-authorization');expect((await store.authorization('fixture-authorization'))?.outcome).toBe('withdrawn');
  expect((await grant()).outcome).toBe('withdrawn');await expect(store.authorize(authorization('other','other-op'),'c'.repeat(64),START,START)).rejects.toThrow();
 });
 it('gives exactly one SQL issuer winner under concurrent reservations',async()=>{
  await grant();const rows=await Promise.all([issuer('b'.repeat(64),'claim-one'),issuer('b'.repeat(64),'claim-two')]);expect(rows[0].claim_id).toBe(rows[1].claim_id);expect(['claim-one','claim-two']).toContain(rows[0].claim_id);
  expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_issuer_once').first('n')).toBe(1);
 });
 it('keeps the original issuer window after delayed auth and fresh transport retry',async()=>{
  await grant();expect((await issuer('b'.repeat(64),'first',START,START+30000)).outcome).toBe('expired');
  expect((await issuer('b'.repeat(64),'second',START+30000,START+30000)).outcome).toBe('expired');expect((await issuer()).original_request_expires_at).toBe(START+30000);
 });
 it('does not recreate a used semantic purpose with a different issuer operation or tuple',async()=>{
  await grant();await issuer();await expect(store.reserveIssuer('fixture-authorization','existing-record','another-operation','c'.repeat(64),o,'different-purpose','claim2',START,START)).rejects.toThrow();
  await expect(issuer('c'.repeat(64))).rejects.toThrow();
 });
 it.each(['owner_binding','device_binding','source_binding','paired_subject_binding_sha256','selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256'] as const)('refuses a changed original %s',async field=>{
  await grant();await expect(store.reserveIssuer('fixture-authorization','existing-record','issuer-operation','b'.repeat(64),{...o,[field]:'f'.repeat(64)},'private-purpose','claim',START,START)).rejects.toThrow('host_wake_authorization_scope');
 });
 it('refuses a different target/platform/environment or original window outside operator scope',async()=>{
  await grant();for(const extra of [{target:{...o.target,installation_id:'other'}},{platform:'ios' as const},{apns_environment:'production' as const},{original_wake_issued_at_ms:START-1},{original_wake_expires_at_ms:END+1,original_display_expires_at_ms:END+1}])await expect(store.reserveIssuer('fixture-authorization','existing-record','issuer-op','b'.repeat(64),{...o,...extra},'private','claim',START,START)).rejects.toThrow();
 });
 it('rotation disables the exact prior principal; a new active row is not purpose lineage',async()=>{
  await grant();await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();await env.DB.prepare("INSERT INTO install_tokens (id,ha_install_id,token_hash,token_prefix) VALUES ('rotated-record','existing-install','different-token-hash','djci_other')").run();
  await expect(issuer()).rejects.toThrow();await expect(store.reserveIssuer('fixture-authorization','rotated-record','issuer-op','b'.repeat(64),o,'private','claim',START,START)).rejects.toThrow('host_wake_principal');
 });
 it('never promotes UNKNOWN, withdrawn, or expired issuer history on a duplicate or finish',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'unknown',START);await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  expect((await issuer()).outcome).toBe('unknown');await store.withdrawAuthorization('fixture-authorization');expect((await store.issuer('fixture-authorization',o.core_purpose_id))?.outcome).toBe('withdrawn');
 });
 it('reserves one native nonce job, not a new nonce after duplicate/lost response',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  const first=await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START);
  const retry=await store.reserveNativeJob('fixture-authorization','existing-record',o,{...c,nonce_b64url:'B'+'A'.repeat(42)},'c'.repeat(64),'app_attest_assertion',START);expect(retry.challenge_json).toBe(first.challenge_json);
  await expect(store.reserveNativeJob('fixture-authorization','existing-record',o,{...c,challenge_id:'33333333-3333-4333-8333-333333333333'},'c'.repeat(64),'app_attest_assertion',START)).rejects.toThrow();
 });
 it('records the authenticated original expired challenge before a fresh request can renew it',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  const first=await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START+30000);expect(first.outcome).toBe('expired');
  const retry=await store.reserveNativeJob('fixture-authorization','existing-record',o,{...c,captured_at_ms:START+30000,expires_at_ms:START+60000},'c'.repeat(64),'app_attest_assertion',START+30000);expect(retry.expires_at).toBe(START+30000);expect(retry.outcome).toBe('expired');
 });
 it('requires actually issued original purpose for a native job and does not mint on status',async()=>{
  await grant();await issuer();await expect(store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START)).rejects.toThrow();expect(await store.nativeJob(c.challenge_id)).toBeNull();
 });
 it('withdraws preallocated purposes and noncejobs without issuing a new row',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START);await store.withdrawAuthorization('fixture-authorization');
  expect((await store.nativeJob(c.challenge_id))?.outcome).toBe('withdrawn');expect(await store.isLive('fixture-authorization','existing-record',START)).toBe(false);
 });
 it('takes one durable native proof claim before crypto, retaining UNKNOWN on loss/retry',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START);
  const claims=await Promise.all(['claim-one','claim-two'].map(claim=>store.claimNativeProof('fixture-authorization','existing-record',c.challenge_id,'app_attest_assertion',claim,START)));expect(claims.filter(Boolean)).toHaveLength(1);
  expect((await store.nativeJob(c.challenge_id))?.outcome).toBe('unknown');expect(await store.claimNativeProof('fixture-authorization','existing-record',c.challenge_id,'app_attest_assertion','claim-three',START)).toBe(false);
 });
 it('does not change expected native proof kind or reuse a nonce for fallback',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START);
  expect(await store.claimNativeProof('fixture-authorization','existing-record',c.challenge_id,'app_attest_attestation','claim',START)).toBe(false);
  await expect(store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_attestation',START)).rejects.toThrow();
 });
 it('does not start proof verification after expiry or principal retirement',async()=>{
  await grant();await issuer();await store.finishIssuer('fixture-authorization',o.core_purpose_id,'issued',START);
  await store.reserveNativeJob('fixture-authorization','existing-record',o,c,'c'.repeat(64),'app_attest_assertion',START);
  expect(await store.claimNativeProof('fixture-authorization','existing-record',c.challenge_id,'app_attest_assertion','claim',START+30000)).toBe(false);
  await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();expect(await store.claimNativeProof('fixture-authorization','existing-record',c.challenge_id,'app_attest_assertion','claim',START)).toBe(false);
 });

});
