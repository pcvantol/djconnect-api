import {env} from 'cloudflare:test';
import {beforeAll,describe,it,expect} from 'vitest';
import installSchema from '../../../migrations/0002_install_tokens.sql?raw';
import {sha256Hex} from '../../../src/crypto';
import {authenticateCore} from '../principal';
import {RequestWindow} from '../request-window';
import {decodeServer,proof,serverRoute,SERVER_PREFIX,SERVER_ROUTES} from '../server-wire';
import {RECEIVING_VERSION} from '../wire';
import vectors from './native-transcript-vectors.json';
const base={version:RECEIVING_VERSION,authorization_id:'authz',issuer_operation_id:'issuer-operation',core_purpose_id:vectors.original.core_purpose_id};
function request(route:string){return new Request('https://local.test'+SERVER_PREFIX+route,{method:'POST'});}
describe('private receiving routes and actual existing djci authentication, no issuer/native admission',()=>{
 beforeAll(async()=>{for(const sql of installSchema.replace(/--[^\n]*/g,'').split(';').filter(x=>x.trim()))await env.DB.prepare(sql).run();});
 it.each(SERVER_ROUTES)('decodes only the exact private %s DTO',route=>{
  const value={...base,...(route==='issuer/issue'?{original:vectors.original}:route.startsWith('native/')?{challenge_id:vectors.challenge.challenge_id,...(route==='native/complete'?{native_proof:{kind:'app_attest_assertion',bytes_b64:'AA=='}}:{})}:{})};
  expect(decodeServer(route,value)).toEqual(value);expect(()=>decodeServer(route,{...value,caller_approved:true})).toThrow();expect(serverRoute(request(route))).toBe(route);
 });
 it('does not accept Apple paired identity or forward its headers to API',()=>{
  const r=request('issuer/status');r.headers.set('x-djconnect-device-id','djconnect-ios-ABCDEF123456');expect(()=>serverRoute(r)).toThrow('host_wake_server_transport');
  expect(()=>decodeServer('issuer/status',{...base,device_id:'djconnect-ios-ABCDEF123456',client_type:'ios'})).toThrow();
 });
 it.each(['issuer/status?','issuer/status?x=1','issuer/status#fragment','issuer/status/','native%2Fstatus'])('rejects query/fragment/path rewrites %s',path=>{expect(()=>serverRoute(request(path))).toThrow();});
 it.each(['Origin','Cookie','X-DJConnect-Client-Type'])('rejects forwarded browser/paired %s',header=>{const r=request('issuer/status');r.headers.set(header,'fixture');expect(()=>serverRoute(r)).toThrow();});
 it('rejects unselected paths, method and scheme',()=>{
  expect(()=>serverRoute(request('prepare'))).toThrow();expect(()=>serverRoute(new Request('https://local.test'+SERVER_PREFIX+'issuer/status'))).toThrow();expect(()=>serverRoute(new Request('http://local.test'+SERVER_PREFIX+'issuer/status',{method:'POST'}))).toThrow();
 });
 it('bounds actual native proof DTO bytes and requires an explicit selected kind',()=>{
  expect(proof({kind:'app_attest_assertion',bytes_b64:btoa('A'.repeat(9216))}).bytes_b64.length).toBe(12288);
  for(const p of [{kind:'opaque',bytes_b64:'AA=='},{kind:'app_attest_assertion',bytes_b64:'AB=='},{kind:'app_attest_assertion',bytes_b64:'AA'},{kind:'app_attest_assertion',bytes_b64:btoa('A'.repeat(9217))},{kind:'app_attest_assertion',bytes_b64:''},{kind:'app_attest_assertion',bytes_b64:'AA==',verified:true}])expect(()=>proof(p)).toThrow();
 });
 it('resolves an actual existing token row and rejects disabled, unknown and ordinary app bearers',async()=>{
  const token='djci_'+'A'.repeat(43),at=Date.now(),w=new RequestWindow(()=>at,new AbortController().signal);
  try{
   await env.DB.prepare("DELETE FROM install_tokens").run();await env.DB.prepare("INSERT INTO install_tokens (id,ha_install_id,token_hash,token_prefix) VALUES ('actual-test-record','fixture-install',?,'djci_fixture')").bind(await sha256Hex(token)).run();
   const r=request('issuer/status');r.headers.set('authorization','Bearer '+token);expect(await authenticateCore(r,env.DB,w)).toEqual({id:'actual-test-record',ha_install_id:'fixture-install'});
   await env.DB.prepare('UPDATE install_tokens SET disabled=1').run();await expect(authenticateCore(r,env.DB,w)).rejects.toThrow('host_wake_core_auth');
   for(const auth of ['Bearer application-device-token','Bearer djchw_'+'A'.repeat(43),'Bearer djci_'+'B'.repeat(43)]){r.headers.set('authorization',auth);await expect(authenticateCore(r,env.DB,w)).rejects.toThrow('host_wake_core_auth');}
  }finally{w.close();}
 });
});
