import {env} from 'cloudflare:test';
import {beforeAll,beforeEach,describe,expect,it,vi} from 'vitest';
import schema from '../schema.sql?raw';
import {createHostAppWakeService,type WakePorts} from '../service';
import {BODY,PREFIX,ROLE,VERSION,decode,original,type OriginalPurpose} from '../wire';
import {WakeStore} from '../store';

// Actual workerd/D1/AES; synthetic original authority, clock, key and transport.
const START=1700000000000,END=START+7200000,KEY=btoa('0123456789abcdef0123456789abcdef');
let at=START,live=true,sequence=0,ports:WakePorts,service:ReturnType<typeof createHostAppWakeService>;
function grant(purpose='original-purpose'):OriginalPurpose{return {version:VERSION,purpose_id:purpose,token_role:ROLE,owner_binding:'a'.repeat(64),device_binding:'b'.repeat(64),source_binding:'c'.repeat(64),target:{host_bundle_id:'dev.djconnect.ios',installation_id:'native-install'},apns_environment:'sandbox',platform:'ios',issued_at_ms:START,expires_at_ms:END,display_expires_at_ms:END,max_operations:8,max_wakes:8};}
function base(operation_id='op-'+(++sequence),purpose_id='original-purpose'){return {version:VERSION,purpose_id,operation_id};}
function registration(extra:Record<string,unknown>={}){return {...base(),generation:'original-generation',revision:1,token_role:ROLE,target:grant().target,apns_environment:'sandbox',apns_token:'ab'.repeat(32),...extra};}
function wake(extra:Record<string,unknown>={}){return {...base(),generation:'original-generation',revision:1,event:'direct_rich_refresh',...extra};}
function make(overrides:Partial<WakePorts>={}){
 const p:WakePorts={db:env.DB,admitOriginalPurpose:vi.fn(async()=>grant()),admitNativeRegistration:vi.fn(async()=>undefined),assertCurrent:vi.fn(()=>{if(!live)throw new Error('original authority withdrawn');}),now:()=>at,encryptionKey:()=>KEY,authorizeProvider:vi.fn(async()=>'synthetic.provider.jwt'),fetcher:vi.fn(async()=>new Response(null,{status:200})) as typeof fetch,capacity:16,...overrides};return {p,s:createHostAppWakeService(p)};
}
async function issue(s=service){return s.issueOriginal({syntheticOriginalProof:true},new AbortController().signal);}
async function call(kind:string,body:unknown,credential:string,s=service,signal?:AbortSignal,extra:Record<string,string>={}){
 return s.handle(new Request('https://local.test'+PREFIX+kind,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+credential,...extra},body:typeof body==='string'?body:JSON.stringify(body),signal}));
}
async function registered(){const i=await issue(),r=registration();expect((await call('register',r,i.credential)).status).toBe(200);return {i,r};}
async function scalar(sql:string){return env.DB.prepare(sql).first('n');}
describe('separate host-app wake actual D1 candidate; no operative admission',()=>{
 beforeAll(async()=>{for(const q of schema.replace(/--[^\n]*/g,'').split(';').filter(s=>s.trim()))await env.DB.prepare(q).run();});
 beforeEach(async()=>{await env.DB.prepare('DELETE FROM host_app_wake_operations').run();await env.DB.prepare('DELETE FROM host_app_wake_purposes').run();at=START;live=true;sequence=0;({p:ports,s:service}=make());});
 it('issues a narrow one-time credential only after the real admission port succeeds',async()=>{
  const i=await issue();expect(i.credential).toMatch(/^djchw_[A-Za-z0-9_-]{43}$/);expect(ports.admitOriginalPurpose).toHaveBeenCalledOnce();expect(ports.assertCurrent).toHaveBeenCalled();
  const row=await env.DB.prepare('SELECT * FROM host_app_wake_purposes').first();expect(JSON.stringify(row)).not.toContain(i.credential);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('consumes original issue identity durably across restart and lost credential response',async()=>{
  await issue();service.close();const x=make();await expect(issue(x.s)).rejects.toThrow('host_wake_issue_consumed_or_capacity');expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_purposes')).toBe(1);
 });
 it('does not create an approval when the original proof supplier refuses',async()=>{
  const x=make({admitOriginalPurpose:async()=>{throw new Error('no original authority');}});await expect(issue(x.s)).rejects.toThrow();expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_purposes')).toBe(0);
 });
 it.each(['admitOriginalPurpose','admitNativeRegistration','assertCurrent','now','encryptionKey','authorizeProvider','fetcher'] as const)('requires explicit server port %s',key=>{
  expect(()=>createHostAppWakeService({...ports,[key]:undefined} as unknown as WakePorts)).toThrow('host_wake_ports');
 });
 it('reserves purpose capacity without evicting used or withdrawn original history',async()=>{
  const x=make({capacity:1});const i=await issue(x.s);await call('revoke',base(),i.credential,x.s);
  const y=make({capacity:1,admitOriginalPurpose:async()=>grant('different-original')});await expect(issue(y.s)).rejects.toThrow('host_wake_issue_consumed_or_capacity');
 });
 it('encrypts actual host token and emits only exact background APNs grammar on fixed host',async()=>{
  const {i,r}=await registered();const raw=JSON.stringify(await env.DB.prepare('SELECT * FROM host_app_wake_purposes').all());expect(raw).not.toContain(r.apns_token);expect(raw).not.toContain(i.credential);
  const response=await call('wake',wake(),i.credential);expect(await response.json()).toMatchObject({operation_state:'provider_accepted'});
  const [url,init]=vi.mocked(ports.fetcher).mock.calls[0];expect(url).toBe('https://api.sandbox.push.apple.com/3/device/'+r.apns_token);expect(init?.body).toBe(BODY);expect(JSON.parse(String(init?.body))).toEqual({aps:{'content-available':1}});
  expect(init?.headers).toMatchObject({'apns-push-type':'background','apns-topic':'dev.djconnect.ios','apns-priority':'5','apns-expiration':String(Math.floor((START+30000)/1000))});expect(init?.redirect).toBe('error');
 });
 it('a client token shape and capability cannot replace genuine native registration admission',async()=>{
  const x=make({admitNativeRegistration:async()=>{throw new Error('no actual native token observation');}});const i=await issue(x.s);expect((await call('register',registration(),i.credential,x.s)).status).toBe(503);expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_operations')).toBe(0);expect(x.p.fetcher).not.toHaveBeenCalled();
 });
 it('withdrawal during native registration admission prevents any target or operation',async()=>{
  const x=make({admitNativeRegistration:async()=>{live=false;}});const i=await issue(x.s);expect((await call('register',registration(),i.credential,x.s)).status).toBe(503);expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_operations')).toBe(0);
 });
 it.each(['widget','live_activity_update','live_activity_start'])('refuses %s token-role reinterpretation',async role=>{
  const i=await issue();expect((await call('register',registration({token_role:role}),i.credential)).status).toBe(400);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it.each(['payload','profile_id','aps','content_state','artwork_url','read_credential','target_url','topic'])('rejects undeclared wake content %s before provider auth',async key=>{
  const {i}=await registered();expect((await call('wake',wake({[key]:'forbidden'}),i.credential)).status).toBe(400);expect(ports.authorizeProvider).not.toHaveBeenCalled();
 });
 it('rejects duplicate and escaped duplicate JSON keys',async()=>{
  const {i}=await registered();const b=JSON.stringify(wake());for(const suffix of [',"event":"direct_rich_refresh"',',"\\u0065vent":"invalidate"'])expect((await call('wake',b.slice(0,-1)+suffix+'}',i.credential)).status).toBe(400);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it.each([{apns_environment:'production'},{target:{host_bundle_id:'dev.other.app',installation_id:'native-install'}},{target:{host_bundle_id:'dev.djconnect.ios',installation_id:'other-install'}}])('refuses an admitted-target binding mismatch %j',async extra=>{
  const i=await issue();expect((await call('register',registration(extra),i.credential)).status).toBe(403);expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_operations')).toBe(0);
 });
 it('separates ordinary legacy and WidgetKit credentials from host wake authority',async()=>{
  for(const c of ['djci_example','djcs_'+'A'.repeat(43),'other'])expect((await call('status',base(),c)).status).toBe(401);
 });
 it('rejects Origin/cookie/browser transport and unknown paths',async()=>{
  const i=await issue();for(const extra of [{origin:'https://client.test'},{cookie:'session=x'}] as Record<string,string>[])expect((await call('status',base(),i.credential,service,undefined,extra)).status).toBe(403);
  expect((await call('issue',base(),i.credential)).status).toBe(404);
 });
 it('allows exactly one competing event dispatch on actual SQLite CAS',async()=>{
  const {i}=await registered();const w=wake();const all=await Promise.all(Array.from({length:5},()=>call('wake',w,i.credential)));expect(all.every(r=>r.status===200)).toBe(true);expect(ports.fetcher).toHaveBeenCalledOnce();expect(await scalar("SELECT COUNT(*) n FROM host_app_wake_operations WHERE kind='wake'")).toBe(1);
 });
 it('replay after service restart is observation-only, never a second APNs call',async()=>{
  const {i}=await registered(),w=wake();await call('wake',w,i.credential);const x=make();expect(await (await call('wake',w,i.credential,x.s)).json()).toMatchObject({operation_state:'provider_accepted'});expect(x.p.fetcher).not.toHaveBeenCalled();
 });
 it('lost APNs acknowledgement stays unknown through restart and status',async()=>{
  ports.fetcher=vi.fn(async()=>{throw new Error('lost response');}) as typeof fetch;service=createHostAppWakeService(ports);const {i}=await registered(),w=wake();
  expect(await (await call('wake',w,i.credential)).json()).toMatchObject({operation_state:'unknown'});const x=make();expect(await (await call('wake',w,i.credential,x.s)).json()).toMatchObject({operation_state:'unknown'});expect(x.p.fetcher).not.toHaveBeenCalled();
 });
 it('a lost SQLite dispatch-marker reply cannot authorize a later retry',async()=>{
  const db=new Proxy(env.DB,{get(target,key){
   if(key==='prepare')return (sql:string)=>{
    const stmt=target.prepare(sql);if(!sql.includes("SET outcome='dispatch_started'"))return stmt;
    const wrap=(s:D1PreparedStatement):D1PreparedStatement=>new Proxy(s,{get(q,k){
     if(k==='bind')return (...args:unknown[])=>wrap(q.bind(...args));
     if(k==='run')return async()=>{await q.run();throw new Error('lost durable marker acknowledgement');};
     const v=Reflect.get(q,k);return typeof v==='function'?v.bind(q):v;
    }});return wrap(stmt);
   };
   const v=Reflect.get(target,key);return typeof v==='function'?v.bind(target):v;
  }});
  const x=make({db});ports=x.p;service=x.s;const {i}=await registered(),w=wake();
  expect(await (await call('wake',w,i.credential)).json()).toMatchObject({operation_state:'unknown'});expect(ports.fetcher).not.toHaveBeenCalled();
  const restarted=make();expect(await (await call('wake',w,i.credential,restarted.s)).json()).toMatchObject({operation_state:'unknown'});expect(restarted.p.fetcher).not.toHaveBeenCalled();
 });
 it('token ciphertext cannot be reopened under a changed encryption key',async()=>{
  const {i}=await registered();const x=make({encryptionKey:()=>btoa('fedcba9876543210fedcba9876543210')});await call('wake',wake(),i.credential,x.s);expect(x.p.authorizeProvider).not.toHaveBeenCalled();expect(x.p.fetcher).not.toHaveBeenCalled();
 });
 it('expiry during authorization consumes the event without sending or renewal',async()=>{
  ports.authorizeProvider=vi.fn(async()=>{at=END;return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered(),w=wake();await call('wake',w,i.credential);expect(ports.fetcher).not.toHaveBeenCalled();expect(await (await call('status',base(w.operation_id),i.credential)).json()).toMatchObject({state:'expired',expires_at_ms:END});
 });
 it('provider rejection is an observation and does not authorize retry',async()=>{
  ports.fetcher=vi.fn(async()=>new Response(null,{status:403})) as typeof fetch;service=createHostAppWakeService(ports);const {i}=await registered(),w=wake();expect(await (await call('wake',w,i.credential)).json()).toMatchObject({operation_state:'provider_rejected',provider_status:403});await call('wake',w,i.credential);expect(ports.fetcher).toHaveBeenCalledOnce();
 });
 it('provider 410 clears only the actual sent generation',async()=>{
  ports.fetcher=vi.fn(async()=>new Response(null,{status:410})) as typeof fetch;service=createHostAppWakeService(ports);const {i}=await registered();await call('wake',wake(),i.credential);expect(await (await call('status',base(),i.credential)).json()).toMatchObject({state:'unregistered'});
 });
 it('rotation changes encrypted token revision and denies the former revision',async()=>{
  const {i}=await registered();await call('register',registration({revision:2,apns_token:'cd'.repeat(32)}),i.credential);
  await call('wake',wake(),i.credential);expect(ports.fetcher).not.toHaveBeenCalled();await call('wake',wake({revision:2}),i.credential);expect(vi.mocked(ports.fetcher).mock.calls[0][0]).toContain('cd'.repeat(32));
 });
 it('conflicting request bytes cannot reuse the original operation identity',async()=>{
  const {i}=await registered(),w=wake();await call('wake',w,i.credential);expect((await call('wake',{...w,revision:2},i.credential)).status).toBe(409);expect(ports.fetcher).toHaveBeenCalledOnce();
 });
 it('retirement remains available after all active-operation budget is consumed',async()=>{
  const x=make({admitOriginalPurpose:async()=>({...grant(),max_operations:1})});ports=x.p;service=x.s;const {i}=await registered();await call('wake',wake(),i.credential);expect(ports.authorizeProvider).not.toHaveBeenCalled();
  expect(await (await call('revoke',base(),i.credential)).json()).toMatchObject({state:'withdrawn'});expect(await scalar('SELECT COUNT(*) n FROM host_app_wake_operations')).toBe(1);
 });
 it('30s coalescing is shared across original purposes for the same actual target',async()=>{
  const {i}=await registered();for(let n=0;n<4;n++)await call('wake',wake(),i.credential);expect(ports.fetcher).toHaveBeenCalledOnce();
  const x=make({admitOriginalPurpose:async()=>grant('second-original')});const ii=await issue(x.s);await call('register',registration({purpose_id:'second-original'}),ii.credential,x.s);await call('wake',wake({purpose_id:'second-original'}),ii.credential,x.s);expect(x.p.authorizeProvider).not.toHaveBeenCalled();
 });
 it('purpose-specific wake budget is separate from operation budget',async()=>{
  const x=make({admitOriginalPurpose:async()=>({...grant(),max_wakes:1})});ports=x.p;service=x.s;const {i}=await registered();await call('wake',wake(),i.credential);at+=30000;await call('wake',wake(),i.credential);expect(ports.fetcher).toHaveBeenCalledOnce();
 });
 it('coalesced invalidation stays terminal on retry and does not spend the send budget',async()=>{
  const x=make({admitOriginalPurpose:async()=>({...grant(),max_wakes:2})});ports=x.p;service=x.s;const {i}=await registered();const first=wake();await call('wake',first,i.credential);const joined=wake();
  expect(await (await call('wake',joined,i.credential)).json()).toMatchObject({operation_state:'coalesced',transport_expires_at_ms:START+30000});at+=30000;
  expect(await (await call('wake',joined,i.credential)).json()).toMatchObject({operation_state:'coalesced',transport_expires_at_ms:START+30000});expect(ports.fetcher).toHaveBeenCalledOnce();
  await call('wake',wake(),i.credential);expect(ports.fetcher).toHaveBeenCalledTimes(2);
 });
 it('original display deadline bounds wake purpose independently of 120s content',async()=>{
  expect(()=>original({...grant(),display_expires_at_ms:END-1})).toThrow();expect(original(grant()).expires_at_ms-START).toBe(7200000);
  expect(()=>original({...grant(),expires_at_ms:START+8*3600000+1,display_expires_at_ms:START+9*3600000})).toThrow();
 });
 it('a 30s transport timeout during authorization cannot be reminted by replay',async()=>{
  ports.authorizeProvider=vi.fn(async()=>{at+=30000;return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered(),w=wake();
  await call('wake',w,i.credential);expect(ports.fetcher).not.toHaveBeenCalled();at+=30000;
  expect(await (await call('wake',w,i.credential)).json()).toMatchObject({operation_state:'not_sent',transport_expires_at_ms:START+30000});expect(ports.authorizeProvider).toHaveBeenCalledOnce();
 });
 it('original pre-auth transport lease survives slow actual D1 authentication and exact replay',async()=>{
  const {i}=await registered();let delay=true;
  const db=new Proxy(env.DB,{get(target,key){
   if(key==='prepare')return (sql:string)=>{
    const stmt=target.prepare(sql);if(!sql.includes('WHERE purpose_id=? AND credential_hash=?'))return stmt;
    const wrap=(s:D1PreparedStatement):D1PreparedStatement=>new Proxy(s,{get(q,k){
     if(k==='bind')return (...args:unknown[])=>wrap(q.bind(...args));
     if(k==='first')return async(...args:unknown[])=>{const row=await q.first(...args as []);if(delay){delay=false;at+=30000;}return row;};
     const v=Reflect.get(q,k);return typeof v==='function'?v.bind(q):v;
    }});return wrap(stmt);
   };
   const v=Reflect.get(target,key);return typeof v==='function'?v.bind(target):v;
  }});
  const x=make({db}),w=wake();expect((await call('wake',w,i.credential,x.s)).status).toBe(409);
  await call('wake',w,i.credential,x.s);expect(x.p.fetcher).not.toHaveBeenCalled();
  expect(await (await call('status',base(w.operation_id),i.credential,x.s)).json()).toMatchObject({operation_state:'expired',transport_expires_at_ms:START+30000});
 });
 it('original pre-auth transport lease survives delayed body and exact replay',async()=>{
  const {i}=await registered(),w=wake();let release!:()=>void;
  const stream=new ReadableStream<Uint8Array>({start(c){release=()=>{at+=30000;c.enqueue(new TextEncoder().encode(JSON.stringify(w)));c.close();};}});
  const request=new Request('https://local.test'+PREFIX+'wake',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+i.credential},body:stream});
  const pending=service.handle(request);release();expect((await pending).status).toBe(409);
  await call('wake',w,i.credential);expect(ports.fetcher).not.toHaveBeenCalled();
  expect(await (await call('status',base(w.operation_id),i.credential)).json()).toMatchObject({operation_state:'expired',transport_expires_at_ms:START+30000});
 });
 it('slow unauthenticated request IDs cannot occupy authenticated expired-history capacity',async()=>{
  const {i}=await registered(),w=wake();let release!:()=>void;
  const stream=new ReadableStream<Uint8Array>({start(c){release=()=>{at+=30000;c.enqueue(new TextEncoder().encode(JSON.stringify(w)));c.close();};}});
  const pending=service.handle(new Request('https://local.test'+PREFIX+'wake',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer djchw_'+'X'.repeat(43)},body:stream}));release();expect((await pending).status).toBe(401);
  expect(await scalar("SELECT COUNT(*) n FROM host_app_wake_operations WHERE kind='wake'")).toBe(0);
  await call('wake',w,i.credential);expect(ports.fetcher).toHaveBeenCalledOnce();
 });
 it('64 actually reserved sends exhaust the original purpose without blocking withdrawal',async()=>{
  const x=make({admitOriginalPurpose:async()=>({...grant(),max_operations:128,max_wakes:64})});ports=x.p;service=x.s;const {i}=await registered();
  for(let n=0;n<65;n++){await call('wake',wake(),i.credential);at+=30000;}
  expect(ports.fetcher).toHaveBeenCalledTimes(64);expect(await (await call('revoke',base(),i.credential)).json()).toMatchObject({state:'withdrawn'});
 });
 it('expiry never renews by rotation, retry or a new operation id',async()=>{
  const {i}=await registered();at=END;expect((await call('wake',wake(),i.credential)).status).toBe(409);expect((await call('register',registration({revision:2}),i.credential)).status).toBe(409);expect(ports.fetcher).not.toHaveBeenCalled();expect(await (await call('status',base(),i.credential)).json()).toMatchObject({expires_at_ms:END,state:'expired'});
  expect(await (await call('revoke',base(),i.credential)).json()).toMatchObject({state:'withdrawn'});
 });
 it('original withdrawal during provider authorization prevents the outbound call',async()=>{
  ports.authorizeProvider=vi.fn(async()=>{live=false;return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered();await call('wake',wake(),i.credential);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('durable registration withdrawal during authorization prevents mark/dispatch',async()=>{
  ports.authorizeProvider=vi.fn(async()=>{await new WakeStore(env.DB).withdraw('original-purpose');return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered();await call('wake',wake(),i.credential);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('registration rotation during authorization prevents old-token dispatch',async()=>{
  let credential='';ports.authorizeProvider=vi.fn(async()=>{await call('register',registration({revision:2,apns_token:'cd'.repeat(32)}),credential);return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered();credential=i.credential;await call('wake',wake(),i.credential);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('request cancellation across authorization prevents the sole outbound call',async()=>{
  const c=new AbortController();ports.authorizeProvider=vi.fn(async()=>{c.abort();return 'synthetic.provider.jwt';});service=createHostAppWakeService(ports);const {i}=await registered();await call('wake',wake(),i.credential,service,c.signal);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('clock rollback permanently retires the service generation',async()=>{
  const {i}=await registered();at=START-1;expect((await call('wake',wake(),i.credential)).status).toBeGreaterThanOrEqual(400);at=START;expect((await call('wake',wake(),i.credential)).status).toBe(503);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('changed server ports retire the service instead of adopting a different provider',async()=>{
  const {i}=await registered();ports.fetcher=vi.fn(async()=>new Response());expect((await call('wake',wake(),i.credential)).status).toBe(503);expect(ports.fetcher).not.toHaveBeenCalled();
 });
 it('no promise or boolean can stand in for synchronous original authority',async()=>{
  for(const value of [true,Promise.resolve()]){const x=make({assertCurrent:(()=>value) as unknown as WakePorts['assertCurrent']});await expect(issue(x.s)).rejects.toThrow('host_wake_authority');}
 });
 it('strict structural decoders refuse accessor fields and overbroad scope',()=>{
  const g=grant();Object.defineProperty(g,'purpose_id',{get:()=>{throw new Error('getter ran');},enumerable:true});expect(()=>original(g)).toThrow('host_wake_invalid');
  expect(()=>original({...grant(),extra_rights:true})).toThrow();expect(()=>decode('wake',{...wake(),event:'activity_update'})).toThrow();
 });
});
