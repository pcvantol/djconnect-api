// LOCAL QUALIFICATION ONLY. Limits downstream work, not all edge traffic/cost.
import {DurableObject} from 'cloudflare:workers';
import {type BudgetIdentity,type BudgetResult} from './allocation-budget';
import {base64Url} from 'djc-existing-crypto';
import {type IngressRoute} from './http-ingress';
import {createComposedHandler,COMPOSED_POLICY,type ComposedEnv,type TrustedIdentityResolver} from './composed-http';
export const REQUEST_NAME='djc-rendezvous-requests/1',REQUEST_POLICY='djc-request-admission-qualification/1';
export interface RequestEnv {REQUEST_ADMISSION:DurableObjectNamespace<RequestAdmission>;REQUEST_POLICY_ENABLED?:string}
interface RequestInput {identity:BudgetIdentity;native:boolean}
const need:(v:unknown)=>asserts v=v=>{if(!v)throw new Error('request_admission_rejected');};
const closed=(v:unknown,names:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...names].sort().join(','));
function copyIdentity(value:BudgetIdentity):BudgetIdentity {
  closed(value,['minute','key']);const id={...value};need(Number.isSafeInteger(id.minute)&&id.minute>=0&&typeof id.key==='string'&&id.key.length===43&&/^[A-Za-z0-9_-]+$/.test(id.key));
  const raw=Uint8Array.from(atob(id.key.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(raw.length===32&&base64Url(raw.buffer)===id.key);return id;
}
export class RequestAdmissionState {
  #ctx:DurableObjectState;#env:RequestEnv;#busy=false;
  constructor(ctx:DurableObjectState,env:RequestEnv){this.#ctx=ctx;this.#env=env;ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_days(day INTEGER PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_minutes(minute INTEGER PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_ips(key TEXT PRIMARY KEY,minute INTEGER NOT NULL,total INTEGER NOT NULL,native INTEGER NOT NULL,expires_at INTEGER NOT NULL)');}
  #policy(){need(this.#env.REQUEST_POLICY_ENABLED===REQUEST_POLICY&&this.#env.REQUEST_ADMISSION.idFromName(REQUEST_NAME).equals(this.#ctx.id));}
  #cleanup(now:number){for(const table of ['request_days','request_minutes','request_ips'])this.#ctx.storage.sql.exec('DELETE FROM '+table+' WHERE expires_at<=?',now);}
  async admit(input:RequestInput):Promise<BudgetResult>{
    if(this.#busy)return {ok:false,error:'service_unavailable'};this.#busy=true;
    try{
      closed(input,['identity','native']);input={identity:copyIdentity(input.identity),native:input.native};need(typeof input.native==='boolean');this.#policy();
      const now=Date.now(),minute=Math.floor(now/60000),day=Math.floor(now/86400000);need(input.identity.minute===minute);const expires=(minute+2)*60000,alarm=await this.#ctx.storage.getAlarm();
      await this.#ctx.storage.setAlarm(Math.min(alarm??expires,expires,(day+1)*86400000));
      return this.#ctx.storage.transactionSync(()=>{
        this.#policy();const at=Date.now();need(at>=now&&Math.floor(at/60000)===minute&&Math.floor(at/86400000)===day);this.#cleanup(at);
        const days=this.#ctx.storage.sql.exec<{count:number}>('SELECT count FROM request_days WHERE day=?',day).toArray()[0]?.count??0;
        const minutes=this.#ctx.storage.sql.exec<{count:number}>('SELECT count FROM request_minutes WHERE minute=?',minute).toArray()[0]?.count??0;
        const ip=this.#ctx.storage.sql.exec<{minute:number;total:number;native:number}>('SELECT minute,total,native FROM request_ips WHERE key=?',input.identity.key).toArray()[0];need(!ip||ip.minute===minute);
        if(days>=1000000||minutes>=10000||(ip?.total??0)>=120||input.native&&(ip?.native??0)>=20||!ip&&this.#ctx.storage.sql.exec<{n:number}>('SELECT COUNT(*) AS n FROM request_ips').one().n>=20000)return {ok:false as const,error:'rate_limited' as const,retry_after_ms:Math.max(1,(minute+1)*60000-at)};
        this.#ctx.storage.sql.exec('INSERT INTO request_days(day,count,expires_at) VALUES(?,1,?) ON CONFLICT(day) DO UPDATE SET count=request_days.count+1',day,(day+1)*86400000);
        this.#ctx.storage.sql.exec('INSERT INTO request_minutes(minute,count,expires_at) VALUES(?,1,?) ON CONFLICT(minute) DO UPDATE SET count=request_minutes.count+1',minute,expires);
        this.#ctx.storage.sql.exec('INSERT INTO request_ips(key,minute,total,native,expires_at) VALUES(?,?,1,?,?) ON CONFLICT(key) DO UPDATE SET total=request_ips.total+1,native=request_ips.native+excluded.native',input.identity.key,minute,input.native?1:0,expires);
        return {ok:true as const};
      });
    }catch{return {ok:false,error:'service_unavailable'};}finally{this.#busy=false;}
  }
  async alarm(){if(this.#busy)throw new Error('request_cleanup_busy');this.#busy=true;try{const next=this.#ctx.storage.transactionSync(()=>{this.#cleanup(Date.now());return this.#ctx.storage.sql.exec<{at:number|null}>('SELECT MIN(expires_at) AS at FROM (SELECT expires_at FROM request_days UNION ALL SELECT expires_at FROM request_minutes UNION ALL SELECT expires_at FROM request_ips)').one().at;});if(next===null)await this.#ctx.storage.deleteAlarm();else await this.#ctx.storage.setAlarm(next);}catch{throw new Error('request_cleanup_failed');}finally{this.#busy=false;}}
}
export class RequestAdmission extends DurableObject<RequestEnv>{
  #state:RequestAdmissionState;
  constructor(ctx:DurableObjectState,env:RequestEnv){super(ctx,env);this.#state=new RequestAdmissionState(ctx,env);}
  admit(input:RequestInput){return this.#state.admit(input);}
  alarm(){return this.#state.alarm();}
}
const nativeRoutes:Record<IngressRoute,boolean>={'/create':false,'/poll':false,'/consume':false,'/cancel':false,'/inspect':true,'/attestation/challenge':true,'/attestation/register':true,'/submit-challenge':true,'/submit':true,'/attestation/delete':true,'/attestation/recover':true};
export function createRequestBudgetedHandler(env?:ComposedEnv&RequestEnv,resolveIdentity?:TrustedIdentityResolver){
  const enabled=()=>env?.COMPOSED_POLICY_ENABLED===COMPOSED_POLICY&&env.REQUEST_POLICY_ENABLED===REQUEST_POLICY&&typeof resolveIdentity==='function';
  return async(request:Request)=>{
    let identity:BudgetIdentity|undefined;const startedAt=Date.now();
    const requestEnabled=()=>enabled()&&Date.now()>=startedAt&&(!identity||identity.minute===Math.floor(Date.now()/60000));
    return createComposedHandler(env,async()=>{need(enabled()&&identity);return {...identity};},async route=>{
      try{
        need(enabled());identity=copyIdentity(await resolveIdentity!(request));need(enabled()&&identity.minute===Math.floor(Date.now()/60000));const original=Date.now();
        const result=await env!.REQUEST_ADMISSION.get(env!.REQUEST_ADMISSION.idFromName(REQUEST_NAME)).admit({identity:{...identity},native:request.method!=='OPTIONS'&&nativeRoutes[route]});
        need(enabled()&&Date.now()>=original&&identity.minute===Math.floor(Date.now()/60000));
        closed(result,result?.ok===true?['ok']:['ok','error',...(result&&Object.hasOwn(result,'retry_after_ms')?['retry_after_ms']:[])]);
        if(result.ok===false){need(result.error==='rate_limited'||result.error==='service_unavailable');if(result.retry_after_ms!==undefined)need(Number.isSafeInteger(result.retry_after_ms)&&result.retry_after_ms>=1&&result.retry_after_ms<=60000);return result;}
        need(result.ok===true);return {ok:true};
      }catch{return {ok:false,error:'service_unavailable'};}
    },requestEnabled)(request);
  };
}
