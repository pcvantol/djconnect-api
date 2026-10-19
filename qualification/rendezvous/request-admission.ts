// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {DurableObject} from 'cloudflare:workers';
import {type BudgetIdentity,type BudgetResult} from './allocation-budget';
import {base64Url} from 'djc-existing-crypto';
import {type IngressRoute} from './http-ingress';
import {createComposedHandler,COMPOSED_POLICY,type ComposedEnv,type TrustedIdentityResolver} from './composed-http';
export const REQUEST_NAME='djc-rendezvous-requests/1',REQUEST_POLICY='djc-request-admission-qualification/2';
export interface RequestEnv {REQUEST_ADMISSION:DurableObjectNamespace<RequestAdmission>;REQUEST_POLICY_ENABLED?:string}
export const REQUEST_LIMITS=Object.freeze({poll:256,create:16,native:64,terminal:16,total:352,regularMinute:9000,totalMinute:10000,regularDay:900000,totalDay:1000000,identities:20000});
export type RequestLane='poll'|'create'|'native'|'terminal';
interface RequestInput {identity:BudgetIdentity;lane:RequestLane}
const tables=['request_days','request_minutes','request_ips','request_ip_partitions','request_terminal_totals'];
const count=(value:number)=>need(Number.isSafeInteger(value)&&value>=0);
type Partition={key:string;minute:number;poll:number;create:number;native:number;terminal:number;expires_at:number}
const need:(v:unknown)=>asserts v=v=>{if(!v)throw new Error('request_admission_rejected');};
const closed=(v:unknown,names:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...names].sort().join(','));
function copyIdentity(value:BudgetIdentity):BudgetIdentity {
  closed(value,['minute','key']);const id={...value};need(Number.isSafeInteger(id.minute)&&id.minute>=0&&typeof id.key==='string'&&id.key.length===43&&/^[A-Za-z0-9_-]+$/.test(id.key));
  const raw=Uint8Array.from(atob(id.key.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(raw.length===32&&base64Url(raw.buffer)===id.key);return id;
}
export class RequestAdmissionState {
  #ctx:DurableObjectState;#env:RequestEnv;#busy=false;
  constructor(ctx:DurableObjectState,env:RequestEnv){this.#ctx=ctx;this.#env=env;ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_days(day INTEGER PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_minutes(minute INTEGER PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_ips(key TEXT PRIMARY KEY,minute INTEGER NOT NULL,total INTEGER NOT NULL,native INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_ip_partitions(key TEXT PRIMARY KEY,minute INTEGER NOT NULL,poll INTEGER NOT NULL,create_count INTEGER NOT NULL,native INTEGER NOT NULL,terminal INTEGER NOT NULL,expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS request_terminal_totals(scope TEXT PRIMARY KEY,count INTEGER NOT NULL,expires_at INTEGER NOT NULL)');}
  #policy(){need(this.#env.REQUEST_POLICY_ENABLED===REQUEST_POLICY&&this.#env.REQUEST_ADMISSION.idFromName(REQUEST_NAME).equals(this.#ctx.id));}
  #cleanup(now:number){for(const table of tables)this.#ctx.storage.sql.exec('DELETE FROM '+table+' WHERE expires_at<=?',now);}
  async admit(input:RequestInput):Promise<BudgetResult>{
    if(this.#busy)return {ok:false,error:'service_unavailable'};this.#busy=true;
    try{
      closed(input,['identity','lane']);input={identity:copyIdentity(input.identity),lane:input.lane};need(['poll','create','native','terminal'].includes(input.lane));this.#policy();
      const now=Date.now(),minute=Math.floor(now/60000),day=Math.floor(now/86400000);need(input.identity.minute===minute);const expires=(minute+2)*60000,alarm=await this.#ctx.storage.getAlarm();
      await this.#ctx.storage.setAlarm(Math.min(alarm??expires,expires,(day+1)*86400000));
      return this.#ctx.storage.transactionSync(()=>{
        this.#policy();const at=Date.now();need(at>=now&&Math.floor(at/60000)===minute&&Math.floor(at/86400000)===day);this.#cleanup(at);
        const sql=this.#ctx.storage.sql,limits=REQUEST_LIMITS;
        const dayRow=sql.exec<{count:number;expires_at:number}>('SELECT count,expires_at FROM request_days WHERE day=?',day).toArray()[0];
        const minuteRow=sql.exec<{count:number;expires_at:number}>('SELECT count,expires_at FROM request_minutes WHERE minute=?',minute).toArray()[0];
        const days=dayRow?.count??0,minutes=minuteRow?.count??0;count(days);count(minutes);need(!dayRow||dayRow.expires_at===(day+1)*86400000);need(!minuteRow||minuteRow.expires_at===expires);
        const terminalCount=(scope:string,total:number,expiry:number)=>{const row=sql.exec<{count:number;expires_at:number}>('SELECT count,expires_at FROM request_terminal_totals WHERE scope=?',scope).toArray()[0];const value=row?.count??0;count(value);need(value<=total&&(!row||row.expires_at===expiry));return value;};
        const dayScope='day:'+day,minuteScope='minute:'+minute;
        const terminalDay=terminalCount(dayScope,days,(day+1)*86400000),terminalMinute=terminalCount(minuteScope,minutes,expires);
        const ip=sql.exec<{key:string;minute:number;total:number;native:number;expires_at:number}>('SELECT * FROM request_ips WHERE key=?',input.identity.key).toArray()[0];
        const partition=sql.exec<Partition>('SELECT key,minute,poll,create_count AS "create",native,terminal,expires_at FROM request_ip_partitions WHERE key=?',input.identity.key).toArray()[0];
        need(Boolean(ip)===Boolean(partition));
        if(ip&&partition){
          count(ip.total);count(ip.native);for(const lane of ['poll','create','native','terminal'] as const)count(partition[lane]);
          need(ip.minute===minute&&partition.minute===minute&&ip.expires_at===expires&&partition.expires_at===expires&&ip.key===partition.key);
          need(partition.poll+partition.create+partition.native+partition.terminal===ip.total&&partition.native===ip.native);
        }
        const denied=()=>({ok:false as const,error:'rate_limited' as const,retry_after_ms:Math.max(1,(minute+1)*60000-at)});
        if(days>=limits.totalDay||minutes>=limits.totalMinute||input.lane!=='terminal'&&(days-terminalDay>=limits.regularDay||minutes-terminalMinute>=limits.regularMinute)||(ip?.total??0)>=limits.total||(partition?.[input.lane]??0)>=limits[input.lane]||!ip&&sql.exec<{n:number}>('SELECT COUNT(*) AS n FROM request_ips').one().n>=limits.identities)return denied();
        sql.exec('INSERT INTO request_days(day,count,expires_at) VALUES(?,1,?) ON CONFLICT(day) DO UPDATE SET count=request_days.count+1',day,(day+1)*86400000);
        sql.exec('INSERT INTO request_minutes(minute,count,expires_at) VALUES(?,1,?) ON CONFLICT(minute) DO UPDATE SET count=request_minutes.count+1',minute,expires);
        sql.exec('INSERT INTO request_ips(key,minute,total,native,expires_at) VALUES(?,?,1,?,?) ON CONFLICT(key) DO UPDATE SET total=request_ips.total+1,native=request_ips.native+excluded.native',input.identity.key,minute,input.lane==='native'?1:0,expires);
        sql.exec('INSERT INTO request_ip_partitions(key,minute,poll,create_count,native,terminal,expires_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET poll=request_ip_partitions.poll+excluded.poll,create_count=request_ip_partitions.create_count+excluded.create_count,native=request_ip_partitions.native+excluded.native,terminal=request_ip_partitions.terminal+excluded.terminal',input.identity.key,minute,input.lane==='poll'?1:0,input.lane==='create'?1:0,input.lane==='native'?1:0,input.lane==='terminal'?1:0,expires);
        if(input.lane==='terminal')for(const [scope,expiry] of [[dayScope,(day+1)*86400000],[minuteScope,expires]] as const)sql.exec('INSERT INTO request_terminal_totals(scope,count,expires_at) VALUES(?,1,?) ON CONFLICT(scope) DO UPDATE SET count=request_terminal_totals.count+1',scope,expiry);
        return {ok:true as const};
      });
    }catch{return {ok:false,error:'service_unavailable'};}finally{this.#busy=false;}
  }
  async alarm(){if(this.#busy)throw new Error('request_cleanup_busy');this.#busy=true;try{const next=this.#ctx.storage.transactionSync(()=>{this.#cleanup(Date.now());return this.#ctx.storage.sql.exec<{at:number|null}>('SELECT MIN(expires_at) AS at FROM (SELECT expires_at FROM request_days UNION ALL SELECT expires_at FROM request_minutes UNION ALL SELECT expires_at FROM request_ips UNION ALL SELECT expires_at FROM request_ip_partitions UNION ALL SELECT expires_at FROM request_terminal_totals)').one().at;});if(next===null)await this.#ctx.storage.deleteAlarm();else await this.#ctx.storage.setAlarm(next);}catch{throw new Error('request_cleanup_failed');}finally{this.#busy=false;}}
}
export class RequestAdmission extends DurableObject<RequestEnv>{
  #state:RequestAdmissionState;
  constructor(ctx:DurableObjectState,env:RequestEnv){super(ctx,env);this.#state=new RequestAdmissionState(ctx,env);}
  admit(input:RequestInput){return this.#state.admit(input);}
  alarm(){return this.#state.alarm();}
}
export const REQUEST_LANES:Readonly<Record<IngressRoute,RequestLane>>=Object.freeze({'/create':'create','/poll':'poll','/consume':'terminal','/cancel':'terminal','/inspect':'native','/attestation/challenge':'native','/attestation/register':'native','/submit-challenge':'native','/submit':'native','/attestation/delete':'native','/attestation/recover':'native'});
export function createRequestBudgetedHandler(env?:ComposedEnv&RequestEnv,resolveIdentity?:TrustedIdentityResolver){
  const enabled=()=>env?.COMPOSED_POLICY_ENABLED===COMPOSED_POLICY&&env.REQUEST_POLICY_ENABLED===REQUEST_POLICY&&typeof resolveIdentity==='function';
  return async(request:Request)=>{
    let identity:BudgetIdentity|undefined;const startedAt=Date.now();
    const requestEnabled=()=>enabled()&&Date.now()>=startedAt&&(!identity||identity.minute===Math.floor(Date.now()/60000));
    return createComposedHandler(env,async()=>{need(enabled()&&identity);return {...identity};},async route=>{
      try{
        need(enabled());identity=copyIdentity(await resolveIdentity!(request));need(enabled()&&identity.minute===Math.floor(Date.now()/60000));const original=Date.now();
        const result=await env!.REQUEST_ADMISSION.get(env!.REQUEST_ADMISSION.idFromName(REQUEST_NAME)).admit({identity:{...identity},lane:REQUEST_LANES[route]});
        need(enabled()&&Date.now()>=original&&identity.minute===Math.floor(Date.now()/60000));
        closed(result,result?.ok===true?['ok']:['ok','error',...(result&&Object.hasOwn(result,'retry_after_ms')?['retry_after_ms']:[])]);
        if(result.ok===false){need(result.error==='rate_limited'||result.error==='service_unavailable');if(result.retry_after_ms!==undefined)need(Number.isSafeInteger(result.retry_after_ms)&&result.retry_after_ms>=1&&result.retry_after_ms<=60000);return result;}
        need(result.ok===true);return {ok:true};
      }catch{return {ok:false,error:'service_unavailable'};}
    },requestEnabled)(request);
  };
}
