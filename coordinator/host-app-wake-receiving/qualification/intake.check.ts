import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,it,expect,vi} from 'vitest';
import schema from '../schema.sql?raw';
import hostSchema from '../../host-app-wake/schema.sql?raw';
import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import {sha256Hex} from '../../../src/crypto';
import {ReceivingStore} from '../receiving-store';
import {receivePrivate,privateScopeHeaders} from '../private-intake';
import {decodeOperatorAuthorization,RECEIVING_VERSION,OPERATOR_AUTHORIZE} from '../wire';
import {SERVER_PREFIX} from '../server-wire';
import type {AppEnv} from '../../../src/types';
import vectors from './native-transcript-vectors.json';
let at:number,store:ReceivingStore;
const token='djci_'+'A'.repeat(43),scope={authorization_id:'authorization',core_purpose_id:vectors.original.core_purpose_id,issuer_operation_id:'issuer-operation'};
const body={version:RECEIVING_VERSION,...scope,original:vectors.original};
const names={authorization_id:'x-djconnect-host-wake-authorization-id',core_purpose_id:'x-djconnect-host-wake-core-purpose-id',issuer_operation_id:'x-djconnect-host-wake-issuer-operation-id'};
function request(value:unknown=body,path='issuer/issue'){
 const h:Record<string,string>={'content-type':'application/json',authorization:'Bearer '+token};for(const k of Object.keys(names) as (keyof typeof names)[])h[names[k]]=scope[k];
 return new Request('https://local.test'+SERVER_PREFIX+path,{method:'POST',headers:h,body:typeof value==='string'?value:JSON.stringify(value)});
}
describe('actual private HTTP prebody principal+scope/once/body binding, no positive native/provider factory',()=>{
 beforeAll(async()=>{for(const text of [installSchema,hostSchema,schema])for(const sql of text.replace(/--[^\n]*/g,'').split(';').filter(x=>x.trim()))await env.DB.prepare(sql).run();});
 beforeEach(async()=>{
  for(const t of ['host_wake_native_pending_policies','host_wake_child_withdrawals','host_wake_receiving_intents','host_wake_native_verifications','host_wake_native_enrollments','host_wake_native_jobs','host_wake_issuer_once','host_wake_operator_authorizations','host_app_wake_operations','host_app_wake_purposes','install_tokens'])await env.DB.prepare('DELETE FROM '+t).run();
  at=Date.now();store=new ReceivingStore(env.DB,16);await env.DB.prepare("INSERT INTO install_tokens(id,ha_install_id,token_hash,token_prefix) VALUES ('record','install',?,'djci_fixture')").bind(await sha256Hex(token)).run();
  const {native_key_id_b64,native_token_sha256,core_purpose_id,operation_id,generation,revision,token_role,original_wake_issued_at_ms,original_wake_expires_at_ms,original_display_expires_at_ms,version,...originalScope}=vectors.original;
  await store.authorize(decodeOperatorAuthorization({version:RECEIVING_VERSION,method:'POST',route:OPERATOR_AUTHORIZE,action:'authorize',operation_id:'operator-op',authorization_id:scope.authorization_id,core_install_token_record_id:'record',ha_install_id:'install',native_key_ref:'native-record',...originalScope,max_original_purpose_ms:28800000,max_operations:256,max_reserved_sends:64,original_authorization_issued_at_ms:at-1000,original_authorization_expires_at_ms:at+3600000}),'a'.repeat(64),at,at);
 });
 async function count(){return env.DB.prepare('SELECT COUNT(*) n FROM host_wake_receiving_intents').first('n');}
 it('authenticates actual existing principal/header scope and durably binds the typed body before returning intake',async()=>{
  const i=await receivePrivate(request(),env as AppEnv,()=>at,16);try{expect(i.principal.id).toBe('record');expect(i.input).toEqual(body);expect(i.intent?.request_hash).toMatch(/^[a-f0-9]{64}$/);expect(await count()).toBe(1);await store.finishIntent(i.intent!,'completed');}finally{i.close();}
 });
 it('cannot remint a window after completed, UNKNOWN, or lost intake response',async()=>{
  const i=await receivePrivate(request(),env as AppEnv,()=>at,16);i.close();
  await expect(receivePrivate(request(),env as AppEnv,()=>at+1000,16)).rejects.toThrow('host_wake_intent_consumed');
  expect((await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue'))?.outcome).toBe('reserved');
  await store.finishIntent(i.intent!,'unknown');await expect(receivePrivate(request(),env as AppEnv,()=>at+2000,16)).rejects.toThrow('host_wake_intent_consumed');
 });
 it('a concurrent loser cannot close or borrow the original winner claim',async()=>{
  const both=await Promise.allSettled([receivePrivate(request(),env as AppEnv,()=>at,16),receivePrivate(request(),env as AppEnv,()=>at,16)]);const wins=both.filter((r):r is PromiseFulfilledResult<Awaited<ReturnType<typeof receivePrivate>>>=>r.status==='fulfilled');expect(wins).toHaveLength(1);try{expect(await count()).toBe(1);expect((await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue'))?.outcome).toBe('reserved');}finally{wins.forEach(x=>x.value.close());}
 });
 it('never allocates semantic history for unknown/disabled principal or missing/malformed headers',async()=>{
  const r=request();r.headers.delete(names.core_purpose_id);await expect(receivePrivate(r,env as AppEnv,()=>at,16)).rejects.toThrow();expect(await count()).toBe(0);
  await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_core_auth');expect(await count()).toBe(0);
 });
 it('rejects combined duplicate/oversized/private nonASCII headers before scope use',()=>{
  for(const value of ['authorization, authorization','A'.repeat(129),'é']){const r=request();r.headers.set(names.authorization_id,value);expect(()=>privateScopeHeaders(r)).toThrow();}
 });
 it('authenticates the original installation ownership before allocating body identity',async()=>{
  await env.DB.prepare("UPDATE host_wake_operator_authorizations SET ha_install_id='different-install'").run();await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_principal_scope');expect(await count()).toBe(0);
 });
 it('binds decoded body IDs to actual authenticated private headers and retains a terminal negative attempt',async()=>{
  await expect(receivePrivate(request({...body,issuer_operation_id:'substituted'}),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_header_body_scope');expect((await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue'))?.outcome).toBe('unknown');
 });
 it.each(['1.0','1e0','-0','9007199254740992'])('rejects raw numeric ambiguity %s without renewing its authenticated intent',async number=>{
  await expect(receivePrivate(request(JSON.stringify(body).replace('"revision":1','"revision":'+number)),env as AppEnv,()=>at,16)).rejects.toThrow();expect(await count()).toBe(1);
 });
 it('closes the original intent after a bounded body failure or duplicate decoded key',async()=>{
  await expect(receivePrivate(request(JSON.stringify(body).slice(0,-1)+',"version":"'+RECEIVING_VERSION+'"}'),env as AppEnv,()=>at,16)).rejects.toThrow();expect((await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue'))?.outcome).toBe('unknown');
 });
 it('status and terminal withdrawal do not allocate new history or require a fresh positive grant',async()=>{
  await store.withdrawAuthorization(scope.authorization_id);
  for(const route of ['issuer/status','issuer/withdraw']){const i=await receivePrivate(request({version:RECEIVING_VERSION,...scope},route),env as AppEnv,()=>at,16);try{expect(i.intent).toBeNull();}finally{i.close();}}
  expect(await count()).toBe(0);
 });
 it('oversized bodies leave one terminal authenticated intent and no issuer/native rows',async()=>{
  await expect(receivePrivate(request(' '.repeat(16385)),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_size');expect(await count()).toBe(1);expect(await env.DB.prepare('SELECT COUNT(*) n FROM host_wake_issuer_once').first('n')).toBe(0);
 });
 it('retains the authenticated original attempt if SQL/body time exceeds the original ten-second body budget',async()=>{
  const actual=ReceivingStore.prototype.reserveIntent;
  const spy=vi.spyOn(ReceivingStore.prototype,'reserveIntent').mockImplementationOnce(async function(this:ReceivingStore,...args){const row=await actual.apply(this,args);at+=11000;return row;});
  try{await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_body_timeout');const row=await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue');expect(row?.outcome).toBe('unknown');expect(row?.expires_at).toBe(at-11000+30000);await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_intent_consumed');}finally{spy.mockRestore();}
 });
 it('retains the authentic original 30-second latch after a committed SQL reply arrives too late',async()=>{
  const actual=ReceivingStore.prototype.reserveIntent;
  const spy=vi.spyOn(ReceivingStore.prototype,'reserveIntent').mockImplementationOnce(async function(this:ReceivingStore,...args){const row=await actual.apply(this,args);at+=31000;return row;});
  try{await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_transport_expired');const row=await store.intent(scope.authorization_id,scope.core_purpose_id,scope.issuer_operation_id,'issuer/issue');expect(row?.expires_at).toBe(at-31000+30000);await expect(receivePrivate(request(),env as AppEnv,()=>at,16)).rejects.toThrow('host_wake_intent_consumed');}finally{spy.mockRestore();}
 });

});
