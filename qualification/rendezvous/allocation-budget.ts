// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
import {DurableObject} from 'cloudflare:workers';
import {base64Url,base64Decode} from 'djc-existing-crypto';
export const BUDGET_NAME='djc-rendezvous-budget/1';
export const BUDGET_POLICY='djc-allocation-qualification/1';
export interface BudgetIdentity {minute:number;key:string}
export type AllocationKind='transaction'|'key';
export interface BudgetRequest {kind:AllocationKind;identity:BudgetIdentity}
export interface BudgetEnv {ADMISSION_STATE:DurableObjectNamespace;ALLOCATION_POLICY_ENABLED?:string}
export type BudgetResult={ok:true}|{ok:false;error:'rate_limited'|'service_unavailable';retry_after_ms?:number};
const need:(v:unknown)=>asserts v=v=>{if(!v)throw new Error('admission_rejected');};
const closed=(v:object,names:string[])=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...names].sort().join(','));
function opaque(v:string){need(typeof v==='string'&&v.length===43&&/^[A-Za-z0-9_-]+$/.test(v));const b=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(b.length===32&&base64Url(b.buffer)===v);}
export function normalizeBudgetIp(trustedEdgeIp:string):string {
  need(typeof trustedEdgeIp==='string'&&trustedEdgeIp.length>0&&trustedEdgeIp.length<=64);
  let ip:string;
  if(trustedEdgeIp.includes(':')){need(/^[a-fA-F0-9:.]+$/.test(trustedEdgeIp));ip=new URL('https://['+trustedEdgeIp+']/').hostname.slice(1,-1);}
  else{const parts=trustedEdgeIp.split('.');need(parts.length===4&&parts.every(v=>/^(0|[1-9][0-9]{0,2})$/.test(v)&&Number(v)<=255));ip=parts.join('.');}
  return ip;
}
export async function deriveBudgetIdentity(trustedEdgeIp:string,secret:string):Promise<BudgetIdentity> {
  try{
  const ip=normalizeBudgetIp(trustedEdgeIp);
  need(typeof secret==='string'&&secret.length===44);const raw=base64Decode(secret);need(raw.length===32&&btoa(String.fromCharCode(...raw))===secret);
  const minute=Math.floor(Date.now()/60000),key=await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const bytes=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(JSON.stringify(['djc-rendezvous-edge-ip/1',minute,ip])));
  return {minute,key:base64Url(bytes)};
  }catch{throw new Error('admission_identity_rejected');}
}
export class AllocationBudgetState {
  #ctx:DurableObjectState;#env:BudgetEnv;#busy=false;
  constructor(ctx:DurableObjectState,env:BudgetEnv){this.#ctx=ctx;this.#env=env;ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS allocation_days(day INTEGER PRIMARY KEY, transactions INTEGER NOT NULL, keys INTEGER NOT NULL, expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS allocation_key_calls(day INTEGER PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)');ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS allocation_ips(key TEXT PRIMARY KEY, minute INTEGER NOT NULL, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)');}
  #policy(){need(this.#env.ALLOCATION_POLICY_ENABLED===BUDGET_POLICY&&this.#env.ADMISSION_STATE.idFromName(BUDGET_NAME).equals(this.#ctx.id));}
  #cleanup(now:number){this.#ctx.storage.sql.exec('DELETE FROM allocation_key_calls WHERE expires_at<=?',now);this.#ctx.storage.sql.exec('DELETE FROM allocation_ips WHERE expires_at<=?',now);this.#ctx.storage.sql.exec('DELETE FROM allocation_days WHERE expires_at<=?',now);}
  async admit(input:BudgetRequest):Promise<BudgetResult>{
    if(this.#busy)return {ok:false,error:'service_unavailable'};this.#busy=true;
    try{
      closed(input,['kind','identity']);closed(input.identity,['minute','key']);input={kind:input.kind,identity:{...input.identity}};need(input.kind==='transaction'||input.kind==='key');opaque(input.identity.key);need(Number.isSafeInteger(input.identity.minute)&&input.identity.minute>=0);
      this.#policy();const now=Date.now(),minute=Math.floor(now/60000),day=Math.floor(now/86400000);need(input.identity.minute===minute);
      const deadline=Math.min((day+1)*86400000,input.kind==='transaction'?(minute+2)*60000:(day+1)*86400000),alarm=await this.#ctx.storage.getAlarm();await this.#ctx.storage.setAlarm(Math.min(alarm??deadline,deadline));
      return this.#ctx.storage.transactionSync(()=>{
        this.#policy();const at=Date.now();need(Math.floor(at/60000)===minute&&Math.floor(at/86400000)===day);this.#cleanup(at);
        const current=this.#ctx.storage.sql.exec<{transactions:number;keys:number}>('SELECT transactions,keys FROM allocation_days WHERE day=?',day).toArray()[0]??{transactions:0,keys:0};
        if(current.transactions>=10000&&input.kind==='transaction'||current.keys>=500&&input.kind==='key')return {ok:false as const,error:'rate_limited' as const,retry_after_ms:60000};
        if(input.kind==='transaction'){
          const bucket=this.#ctx.storage.sql.exec<{minute:number;count:number}>('SELECT minute,count FROM allocation_ips WHERE key=?',input.identity.key).toArray()[0];need(!bucket||bucket.minute===minute);
          if(bucket&&bucket.count>=5)return {ok:false as const,error:'rate_limited' as const,retry_after_ms:Math.max(1,(minute+1)*60000-at)};
          if(!bucket&&this.#ctx.storage.sql.exec<{n:number}>('SELECT COUNT(*) AS n FROM allocation_ips').toArray()[0].n>=10000)return {ok:false as const,error:'rate_limited' as const,retry_after_ms:60000};
          this.#ctx.storage.sql.exec('INSERT INTO allocation_ips(key,minute,count,expires_at) VALUES(?,?,1,?) ON CONFLICT(key) DO UPDATE SET count=allocation_ips.count+1',input.identity.key,minute,(minute+2)*60000);
          current.transactions++;
        }else current.keys++;
        this.#ctx.storage.sql.exec('INSERT INTO allocation_days(day,transactions,keys,expires_at) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET transactions=excluded.transactions,keys=excluded.keys',day,current.transactions,current.keys,(day+1)*86400000);
        return {ok:true as const};
      });
    }catch{return {ok:false,error:'service_unavailable'};}finally{this.#busy=false;}
  }
  async admitKeyCall():Promise<BudgetResult>{
    if(this.#busy)return {ok:false,error:'service_unavailable'};this.#busy=true;
    try{
      this.#policy();const now=Date.now(),day=Math.floor(now/86400000),deadline=(day+1)*86400000;
      const alarm=await this.#ctx.storage.getAlarm();await this.#ctx.storage.setAlarm(Math.min(alarm??deadline,deadline));
      return this.#ctx.storage.transactionSync(()=>{
        this.#policy();const at=Date.now();need(at>=now&&Math.floor(at/86400000)===day);this.#cleanup(at);
        const count=this.#ctx.storage.sql.exec<{count:number}>('SELECT count FROM allocation_key_calls WHERE day=?',day).toArray()[0]?.count??0;
        if(count>=50000)return {ok:false as const,error:'rate_limited' as const,retry_after_ms:60000};
        this.#ctx.storage.sql.exec('INSERT INTO allocation_key_calls(day,count,expires_at) VALUES(?,1,?) ON CONFLICT(day) DO UPDATE SET count=allocation_key_calls.count+1',day,deadline);
        return {ok:true as const};
      });
    }catch{return {ok:false,error:'service_unavailable'};}finally{this.#busy=false;}
  }
  async alarm(){if(this.#busy)throw new Error('qualification_cleanup_busy');this.#busy=true;try{const next=this.#ctx.storage.transactionSync(()=>{this.#cleanup(Date.now());return this.#ctx.storage.sql.exec<{at:number|null}>('SELECT MIN(expires_at) AS at FROM (SELECT expires_at FROM allocation_ips UNION ALL SELECT expires_at FROM allocation_days UNION ALL SELECT expires_at FROM allocation_key_calls)').toArray()[0]?.at;});if(next===null||next===undefined)await this.#ctx.storage.deleteAlarm();else await this.#ctx.storage.setAlarm(next);}catch{throw new Error('qualification_cleanup_failed');}finally{this.#busy=false;}}
}
export class AllocationBudget extends DurableObject<BudgetEnv> {
  #state:AllocationBudgetState;
  constructor(ctx:DurableObjectState,env:BudgetEnv){super(ctx,env);this.#state=new AllocationBudgetState(ctx,env);}
  admit(input:BudgetRequest){return this.#state.admit(input);}
  admitKeyCall(...args:unknown[]){return args.length===0?this.#state.admitKeyCall():{ok:false as const,error:'service_unavailable' as const};}
  alarm(){return this.#state.alarm();}
}
